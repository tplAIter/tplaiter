//go:build darwin || linux

package runtimeassembly

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/tplAIter/tplaiter/internal/stateledger"
)

type heldWriter struct {
	dir  *os.File
	file *os.File
	root string
	name string
}
type writerLocks struct {
	locks       []heldWriter
	project     *os.File
	projectPath string
}

func (h *writerLocks) close() {
	if h.project != nil {
		defer h.project.Close()
	}
	for i := len(h.locks) - 1; i >= 0; i-- {
		_ = unix.Flock(int(h.locks[i].file.Fd()), unix.LOCK_UN)
		_ = h.locks[i].file.Close()
		_ = h.locks[i].dir.Close()
	}
}

func holdWriters(ctx context.Context, root, home string) (*writerLocks, error) {
	h := &writerLocks{projectPath: root}
	fail := func(err error) (*writerLocks, error) { h.close(); return nil, err }
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) || canonicalRoot != root {
		return fail(stateledger.ErrUnsafe)
	}
	rootfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	h.project = os.NewFile(uintptr(rootfd), root)
	// Same acquisition order as engine: project, then home. Nonblocking locks
	// avoid deadlock with naming migration or a writer owning the other inode.
	for _, location := range []struct{ dir, name string }{{filepath.Join(root, stateledger.StateDir), "update.lock"}, {home, ".lock"}} {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		canonical, err := filepath.EvalSymlinks(location.dir)
		if err != nil || !filepath.IsAbs(location.dir) || canonical != location.dir {
			return fail(stateledger.ErrUnsafe)
		}
		fd, err := unix.Open(location.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		dir := os.NewFile(uintptr(fd), location.dir)
		// O_NOFOLLOW is applied relative to the held directory, never an unchecked
		// caller path. Only persistent advisory files may be created.
		lockfd, err := unix.Openat(fd, location.name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			_ = dir.Close()
			return fail(err)
		}
		file := os.NewFile(uintptr(lockfd), location.name)
		info, err := file.Stat()
		var stat unix.Stat_t
		if err == nil {
			err = unix.Fstat(lockfd, &stat)
		}
		if err == nil && (!info.Mode().IsRegular() || stat.Nlink != 1 || info.Mode().Perm() != 0o600) {
			err = stateledger.ErrUnsafe
		}
		if err == nil {
			err = unix.Flock(lockfd, unix.LOCK_EX|unix.LOCK_NB)
		}
		if err != nil {
			_ = file.Close()
			_ = dir.Close()
			return fail(fmt.Errorf("stateledger: writer lock unavailable: %w", err))
		}
		h.locks = append(h.locks, heldWriter{dir, file, location.dir, location.name})
	}
	if err := h.check(ctx); err != nil {
		return fail(err)
	}
	return h, nil
}

func (h *writerLocks) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	oldRoot, err := h.project.Stat()
	if err != nil {
		return err
	}
	currentRoot, err := os.Lstat(h.projectPath)
	if err != nil {
		return err
	}
	if !os.SameFile(oldRoot, currentRoot) || !currentRoot.IsDir() {
		return stateledger.ErrUnsafe
	}
	for _, lock := range h.locks {
		old, err := lock.dir.Stat()
		if err != nil {
			return err
		}
		current, err := os.Lstat(lock.root)
		if err != nil {
			return err
		}
		if !os.SameFile(old, current) || !current.IsDir() {
			return stateledger.ErrUnsafe
		}
		old, err = lock.file.Stat()
		if err != nil {
			return err
		}
		current, err = os.Lstat(filepath.Join(lock.root, lock.name))
		if err != nil {
			return err
		}
		if !os.SameFile(old, current) || !current.Mode().IsRegular() {
			return stateledger.ErrUnsafe
		}
	}
	return nil
}

func (h *writerLocks) bindMigrationWriter(ctx context.Context) (*stateledger.BoundMigrationWriter, error) {
	if len(h.locks) != 2 {
		return nil, stateledger.ErrUnsafe
	}
	return stateledger.BindMigrationWriter(ctx, h.projectPath, h.project, h.locks[0].dir, h.locks[1].dir, h.locks[0].file, h.locks[1].file)
}
