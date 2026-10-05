//go:build darwin || linux

package stateledger

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// BoundMigrationWriter retains concrete directory and advisory-lock inodes.
// It is confinement, not trust authority: the concrete assembly separately
// authenticates its runtime and plan while holding the actual writer locks.
type BoundMigrationWriter struct {
	rootPath                                 string
	root, state, home, projectLock, homeLock *os.File
	homePath                                 string
	before                                   map[string]unix.Stat_t
	digests                                  map[string][32]byte
}

// BindMigrationWriter duplicates already-held coordination descriptors. It
// never discovers authority or obtains a substitute lock through a raced path.
func BindMigrationWriter(ctx context.Context, root string, project, state, home, projectLock, homeLock *os.File) (*BoundMigrationWriter, error) {
	b := &BoundMigrationWriter{rootPath: root, before: map[string]unix.Stat_t{}, digests: map[string][32]byte{}}
	duplicate := func(source *os.File) (*os.File, error) {
		if source == nil {
			return nil, ErrUnsafe
		}
		fd, err := unix.Dup(int(source.Fd()))
		if err != nil {
			return nil, err
		}
		unix.CloseOnExec(fd)
		return os.NewFile(uintptr(fd), source.Name()), nil
	}
	var err error
	sources := []*os.File{project, state, home, projectLock, homeLock}
	destinations := []**os.File{&b.root, &b.state, &b.home, &b.projectLock, &b.homeLock}
	for i, source := range sources {
		*destinations[i], err = duplicate(source)
		if err != nil {
			b.Close()
			return nil, err
		}
	}
	b.homePath = home.Name()
	if err := b.Check(ctx); err != nil {
		b.Close()
		return nil, err
	}
	for _, name := range []string{"project.yaml", DependencyLockFile} {
		var st unix.Stat_t
		if err := unix.Fstatat(int(b.state.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			b.Close()
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			b.Close()
			return nil, ErrUnsafe
		}
		b.before[name] = st
		data, err := b.readTarget(name, st)
		if err != nil {
			b.Close()
			return nil, err
		}
		b.digests[name] = sha256.Sum256(data)
	}
	return b, nil
}

func (b *BoundMigrationWriter) Close() {
	if b != nil {
		for _, f := range []*os.File{b.root, b.state, b.home, b.projectLock, b.homeLock} {
			if f != nil {
				_ = f.Close()
			}
		}
	}
}

// Check observes current directory and lock bindings without following child
// symlinks; checking after inner re-planning is mandatory before publication.
func (b *BoundMigrationWriter) Check(ctx context.Context) error {
	if ctx == nil || b == nil {
		return ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	samePath := func(file *os.File, path string) error {
		held, err := file.Stat()
		if err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnsafe, err)
		}
		if !os.SameFile(held, current) || held.Mode() != current.Mode() {
			return ErrUnsafe
		}
		return nil
	}
	sameAt := func(parent *os.File, name string, held *os.File) error {
		var old, current unix.Stat_t
		if err := unix.Fstat(int(held.Fd()), &old); err != nil {
			return err
		}
		if err := unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsafe, err)
		}
		if old.Dev != current.Dev || old.Ino != current.Ino || old.Mode != current.Mode || current.Nlink != 1 && current.Mode&unix.S_IFMT == unix.S_IFREG {
			return ErrUnsafe
		}
		return nil
	}
	if err := samePath(b.root, b.rootPath); err != nil {
		return err
	}
	if err := sameAt(b.root, StateDir, b.state); err != nil {
		return err
	}
	if err := samePath(b.home, b.homePath); err != nil {
		return err
	}
	if err := sameAt(b.state, "update.lock", b.projectLock); err != nil {
		return err
	}
	return sameAt(b.home, ".lock", b.homeLock)
}

func (b *BoundMigrationWriter) write(ctx context.Context, name string, data []byte) error {
	if name != "project.yaml" && name != DependencyLockFile {
		return ErrUnsafe
	}
	if err := b.Check(ctx); err != nil {
		return err
	}
	checkTarget := func() error {
		old, ok := b.before[name]
		if !ok {
			return ErrUnsafe
		}
		var current unix.Stat_t
		if err := unix.Fstatat(int(b.state.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsafe, err)
		}
		if old.Dev != current.Dev || old.Ino != current.Ino || old.Mode != current.Mode || old.Size != current.Size || old.Mtim != current.Mtim || current.Nlink != 1 {
			return ErrUnsafe
		}
		data, err := b.readTarget(name, current)
		if err != nil {
			return err
		}
		if sha256.Sum256(data) != b.digests[name] {
			return ErrUnsafe
		}
		return nil
	}
	if err := checkTarget(); err != nil {
		return err
	}
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return err
	}
	temp := "." + name + ".tmp-" + hex.EncodeToString(entropy)
	fd, err := unix.Openat(int(b.state.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temp)
	defer func() { _ = unix.Unlinkat(int(b.state.Fd()), temp, 0) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := failpoint("before-rename", name); err != nil {
		return err
	}
	if err := b.Check(ctx); err != nil {
		return err
	}
	if err := checkTarget(); err != nil {
		return err
	}
	// Both operands are relative to the retained state fd. An external directory
	// replacement cannot redirect publication into the foreign replacement.
	if err := unix.Renameat(int(b.state.Fd()), temp, int(b.state.Fd()), name); err != nil {
		return err
	}
	if err := failpoint("before-dir-sync", name); err != nil {
		return err
	}
	if err := b.state.Sync(); err != nil {
		return err
	}
	if err := b.Check(ctx); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(int(b.state.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	b.before[name] = current
	b.digests[name] = sha256.Sum256(data)
	return nil
}

func (b *BoundMigrationWriter) readTarget(name string, expected unix.Stat_t) ([]byte, error) {
	fd, err := unix.Openat(int(b.state.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, err
	}
	if opened.Dev != expected.Dev || opened.Ino != expected.Ino || opened.Mode != expected.Mode || opened.Nlink != 1 || opened.Size > 8<<20 {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, ErrUnsafe
	}
	return data, nil
}

// ApplyPlanBoundContext keeps the compatibility planner's final re-plan while
// publishing only through the retained directory and lock bindings.
func ApplyPlanBoundContext(ctx context.Context, root string, opts Options, digest string, bound *BoundMigrationWriter) (*MigrationPlan, error) {
	if bound == nil || bound.rootPath != root {
		return nil, ErrUnsafe
	}
	return ApplyPlanContext(ctx, root, opts, digest, bound)
}
