//go:build darwin || linux

package ossinstall

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type fileHandle struct {
	file *os.File
}

func (f *fileHandle) close() error {
	if f == nil || f.file == nil {
		return nil
	}
	file := f.file
	f.file = nil
	errUnlock := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	errClose := file.Close()
	if errUnlock != nil {
		return errUnlock
	}
	return errClose
}

type lockSpec struct {
	path string
	mode os.FileMode
}

func acquireInstallLocks(ctx context.Context, root, destination string) (*InstallLocks, error) {
	if ctx == nil {
		return nil, errors.New("ossinstall: nil install lock context")
	}
	root, err := canonicalResourcePath(root)
	if err != nil {
		return nil, err
	}
	destination, err = canonicalResourcePath(destination)
	if err != nil {
		return nil, err
	}
	if root != "" && destination != "" && pathsOverlap(root, destination) {
		return nil, fmt.Errorf("ossinstall: trust root and destination overlap: %s and %s", root, destination)
	}
	// Validate all existing ancestors and leaves before creating any missing
	// directory or lock artifact. This is a no-side-effect preflight.
	if root != "" {
		if err := validateResourcePath(root, false); err != nil {
			return nil, err
		}
	}
	if destination != "" {
		if err := validateResourcePath(destination, true); err != nil {
			return nil, err
		}
	}

	specs := []lockSpec{}
	if root != "" {
		rootParent, err := prepareCanonicalParent(root, 0o700)
		if err != nil {
			return nil, fmt.Errorf("ossinstall: prepare trust-root parent: %w", err)
		}
		if err := validateInstallLeaf(root, rootParent, false); err != nil {
			return nil, err
		}
		specs = append(specs, lockSpec{path: filepath.Join(rootParent, "."+filepath.Base(root)+".tplaiter-install.lock")})
	}
	if destination != "" {
		destinationParent, e := prepareCanonicalParent(destination, 0o755)
		if e != nil {
			return nil, fmt.Errorf("ossinstall: prepare destination parent: %w", e)
		}
		if e := validateInstallLeaf(destination, destinationParent, true); e != nil {
			return nil, e
		}
		specs = append(specs, lockSpec{path: filepath.Join(destinationParent, "."+filepath.Base(destination)+".tplaiter-destination.lock")})
	}
	if len(specs) == 0 {
		return nil, errors.New("ossinstall: no install resource to lock")
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].path < specs[j].path })
	unique := specs[:0]
	for _, spec := range specs {
		if len(unique) == 0 || unique[len(unique)-1].path != spec.path {
			unique = append(unique, spec)
		}
	}

	locks := &InstallLocks{}
	for _, spec := range unique {
		f, e := acquireLock(ctx, spec.path)
		if e != nil {
			_ = locks.Close()
			return nil, e
		}
		locks.files = append(locks.files, &lockFile{file: f, path: spec.path})
	}
	return locks, nil
}

func prepareCanonicalParent(path string, mode os.FileMode) (string, error) {
	abs, err := canonicalResourcePath(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	fd, canonical, missing, err := openExistingPrefix(parent)
	if err != nil {
		return "", err
	}
	for _, part := range missing {
		if err := unix.Mkdirat(int(fd.Fd()), part, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = fd.Close()
			return "", err
		}
		nextFD, err := unix.Openat(int(fd.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = fd.Close()
			return "", err
		}
		if err := fd.Close(); err != nil {
			_ = unix.Close(nextFD)
			return "", err
		}
		fd = os.NewFile(uintptr(nextFD), filepath.Join(canonical, part))
		canonical = filepath.Join(canonical, part)
	}
	if err := fd.Close(); err != nil {
		return "", err
	}
	return canonical, nil
}

func canonicalResourcePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if filepath.Clean(abs) != abs || !filepath.IsAbs(abs) {
		return "", errors.New("noncanonical absolute path")
	}
	return abs, nil
}

func pathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func openExistingPrefix(path string) (*os.File, string, []string, error) {
	path, err := canonicalResourcePath(path)
	if err != nil {
		return nil, "", nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", nil, err
	}
	file := os.NewFile(uintptr(fd), "/")
	canonical := "/"
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(int(file.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			return file, canonical, append([]string{}, parts[i:]...), nil
		}
		if openErr != nil {
			_ = file.Close()
			return nil, "", nil, fmt.Errorf("ancestor %q is not a canonical directory: %w", filepath.Join(canonical, part), openErr)
		}
		if err := file.Close(); err != nil {
			_ = unix.Close(next)
			return nil, "", nil, err
		}
		canonical = filepath.Join(canonical, part)
		file = os.NewFile(uintptr(next), canonical)
	}
	return file, canonical, nil, nil
}

func validateResourcePath(path string, destination bool) error {
	path, err := canonicalResourcePath(path)
	if err != nil {
		return err
	}
	parent, _, _, err := openExistingPrefix(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := parent.Close(); err != nil {
		return err
	}
	return validateInstallLeaf(path, filepath.Dir(path), destination)
}

func validateInstallLeaf(path, parent string, destination bool) error {
	if filepath.Dir(path) != parent {
		return fmt.Errorf("ossinstall: path parent is not canonical: %s", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ossinstall: install path is a symlink: %s", path)
	}
	if destination {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("ossinstall: destination is not an absent or regular file: %s", path)
		}
		if !singleLink(info) {
			return fmt.Errorf("ossinstall: destination is not a regular single-link file: %s", path)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("ossinstall: install root is not a directory: %s", path)
	}
	return nil
}

func validateDestinationPath(path string) error {
	path, err := canonicalResourcePath(path)
	if err != nil {
		return err
	}
	parent, _, _, err := openExistingPrefix(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := parent.Close(); err != nil {
		return err
	}
	return validateInstallLeaf(path, filepath.Dir(path), true)
}

func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func acquireLock(ctx context.Context, path string) (*fileHandle, error) {
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	leaf := filepath.Base(path)
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	handle := &fileHandle{file: f}
	if err := validateLockFile(path, f); err != nil {
		_ = handle.close()
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = handle.close()
			return nil, err
		}
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			if e := validateLockFile(path, f); e != nil {
				_ = handle.close()
				return nil, e
			}
			return handle, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			_ = handle.close()
			return nil, fmt.Errorf("flock %s: %w", path, err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = handle.close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func validateLockFile(path string, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSetuid|info.Mode()&os.ModeSetgid|info.Mode()&os.ModeSticky != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fmt.Errorf("ossinstall: lock %q is not a regular 0600 single-link file", path)
	}
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, lstat) {
		return fmt.Errorf("ossinstall: lock %q path changed or is a symlink", path)
	}
	return nil
}

const maxBuiltExecutableBytes = 256 << 20

// publicationPhaseHook is a typed test-only seam. It has no production input
// path and is used only to make the pre-rename substitution and post-rename
// durability classifications observable in focused tests.
type publicationPhase string

const (
	publicationBeforeRename publicationPhase = "before-rename"
	publicationAfterRename  publicationPhase = "after-rename"
)

var publicationPhaseHook func(publicationPhase, string) error

func publishExecutable(source, destination string) (result PublicationResult, err error) {
	src, err := os.Open(source)
	if err != nil {
		return result, err
	}
	srcInfo, err := src.Stat()
	if err != nil {
		_ = src.Close()
		return result, err
	}
	if !srcInfo.Mode().IsRegular() {
		_ = src.Close()
		return result, fmt.Errorf("ossinstall: build output is not a regular file")
	}
	if srcInfo.Size() < 0 || srcInfo.Size() > maxBuiltExecutableBytes {
		_ = src.Close()
		return result, fmt.Errorf("ossinstall: build output exceeds bounded publication size")
	}

	parent, err := openDirectory(filepath.Dir(destination))
	if err != nil {
		_ = src.Close()
		return result, err
	}
	tempName := ""
	closeParent := func(cause error) (PublicationResult, error) {
		if tempName != "" {
			_ = unix.Unlinkat(int(parent.Fd()), tempName, 0)
		}
		closeErr := parent.Close()
		return result, errors.Join(cause, closeErr)
	}

	leaf := filepath.Base(destination)
	expected, err := snapshotDestination(destination)
	if err != nil {
		_ = src.Close()
		return closeParent(err)
	}
	temp, name, err := openPublicationTemp(parent)
	if err != nil {
		_ = src.Close()
		return closeParent(err)
	}
	tempName = name
	copyErr := func() error {
		written, err := io.CopyN(temp, src, srcInfo.Size())
		if err != nil {
			return err
		}
		if written != srcInfo.Size() {
			return fmt.Errorf("ossinstall: bounded build copy length mismatch")
		}
		if err := temp.Chmod(0o755); err != nil {
			return err
		}
		if err := temp.Sync(); err != nil {
			return err
		}
		return nil
	}()
	if closeErr := src.Close(); copyErr == nil && closeErr != nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = temp.Close()
		return closeParent(copyErr)
	}
	if err := temp.Close(); err != nil {
		return closeParent(err)
	}
	if info, statErr := os.Stat(filepath.Join(parent.Name(), tempName)); statErr != nil || !info.Mode().IsRegular() || !singleLink(info) {
		if statErr == nil {
			statErr = fmt.Errorf("ossinstall: publication temp is not a regular single-link file")
		}
		return closeParent(statErr)
	}
	if publicationPhaseHook != nil {
		if err := publicationPhaseHook(publicationBeforeRename, destination); err != nil {
			return closeParent(err)
		}
	}
	current, err := snapshotDestination(destination)
	if err != nil {
		return closeParent(err)
	}
	if !sameDestination(expected, current) {
		return closeParent(fmt.Errorf("ossinstall: destination leaf changed before publication: %s", destination))
	}
	if err := unix.Renameat(int(parent.Fd()), tempName, int(parent.Fd()), leaf); err != nil {
		return closeParent(fmt.Errorf("rename publication %s: %w", destination, err))
	}
	tempName = ""
	result.Committed = true
	var postErr error
	if publicationPhaseHook != nil {
		postErr = errors.Join(postErr, publicationPhaseHook(publicationAfterRename, destination))
	}
	postErr = errors.Join(postErr, parent.Sync())
	postErr = errors.Join(postErr, parent.Close())
	return result, postErr
}

func openPublicationTemp(parent *os.File) (*os.File, string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name := fmt.Sprintf(".tplaiter-publication-%d-%d.tmp", os.Getpid(), time.Now().UnixNano()+int64(attempt))
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), name, nil
	}
	return nil, "", errors.New("ossinstall: cannot allocate publication temp")
}

func snapshotDestination(destination string) (os.FileInfo, error) {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !singleLink(info) {
		return nil, fmt.Errorf("ossinstall: destination is not an absent regular single-link file: %s", destination)
	}
	return info, nil
}

func sameDestination(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return expected == nil && current == nil
	}
	return os.SameFile(expected, current)
}
