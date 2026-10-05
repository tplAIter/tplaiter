//go:build darwin || linux

package runtimeassembly

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

type readLocation struct {
	path, name string
	dir, file  *os.File
}
type readCoordination struct {
	root      *os.File
	rootPath  string
	locations []readLocation
}

func (h *readCoordination) close() {
	for i := len(h.locations) - 1; i >= 0; i-- {
		l := h.locations[i]
		if l.file != nil {
			_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
			_ = l.file.Close()
		}
		_ = l.dir.Close()
	}
	if h.root != nil {
		_ = h.root.Close()
	}
}

func (h *readCoordination) complete() bool {
	if len(h.locations) != 2 {
		return false
	}
	for _, l := range h.locations {
		if l.file == nil {
			return false
		}
	}
	return true
}

func holdReaders(ctx context.Context, root, home string) (*readCoordination, error) {
	h := &readCoordination{rootPath: root}
	fail := func(err error) (*readCoordination, error) { h.close(); return nil, err }
	openDir := func(path string) (*os.File, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(path) || canonical != path {
			return nil, stateledger.ErrUnsafe
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	var err error
	h.root, err = openDir(root)
	if err != nil {
		return fail(err)
	}
	locations := []struct{ path, name string }{{filepath.Join(root, stateledger.StateDir), "update.lock"}}
	if home != "" {
		locations = append(locations, struct{ path, name string }{home, ".lock"})
	}
	for _, loc := range locations {
		dir, err := openDir(loc.path)
		if err != nil {
			return fail(err)
		}
		l := readLocation{path: loc.path, name: loc.name, dir: dir}
		fd, err := unix.Openat(int(dir.Fd()), loc.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			_ = dir.Close()
			return fail(stateledger.ErrUnsafe)
		}
		if err == nil {
			l.file = os.NewFile(uintptr(fd), loc.name)
			var st unix.Stat_t
			err = unix.Fstat(fd, &st)
			if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o777 != 0o600) {
				err = stateledger.ErrUnsafe
			}
			if err == nil {
				err = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
			}
			if err != nil {
				_ = l.file.Close()
				_ = dir.Close()
				if errors.Is(err, unix.EWOULDBLOCK) {
					return fail(&JournalError{Status: inventory.StatusActive})
				}
				return fail(err)
			}
		}
		h.locations = append(h.locations, l)
	}
	if err := h.check(ctx); err != nil {
		return fail(err)
	}
	return h, nil
}

func (h *readCoordination) check(ctx context.Context) error {
	if ctx == nil {
		return stateledger.ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	same := func(f *os.File, path string) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(info, current) || info.Mode() != current.Mode() {
			return stateledger.ErrUnsafe
		}
		return nil
	}
	if err := same(h.root, h.rootPath); err != nil {
		return err
	}
	for _, l := range h.locations {
		if err := same(l.dir, l.path); err != nil {
			return err
		}
		path := filepath.Join(l.path, l.name)
		if l.file != nil {
			if err := same(l.file, path); err != nil {
				return err
			}
		} else {
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				return &JournalError{Status: inventory.StatusActive}
			}
		}
	}
	return nil
}
