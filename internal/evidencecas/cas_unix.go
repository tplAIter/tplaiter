//go:build darwin || linux

package evidencecas

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type casRoot struct{ fd int }

func openCASRoot(name string) (*casRoot, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("evidencecas: root must be a clean absolute path")
	}
	fd, err := openDir(unix.AT_FDCWD, string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("evidencecas: open filesystem root: %w", err)
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		next, e := openDir(fd, part)
		if e != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("evidencecas: open root component %q: %w", part, e)
		}
		unix.Close(fd)
		fd = next
	}
	return &casRoot{fd: fd}, nil
}

func openDir(parent int, name string) (int, error) {
	for {
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return -1, err
		}
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return -1, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return -1, errors.New("not a directory")
		}
		return fd, nil
	}
}

func (r *casRoot) read(h string) ([]byte, error) {
	dir, e := openDir(r.fd, "sha256")
	if e != nil {
		return nil, e
	}
	defer unix.Close(dir)
	shard, e := openDir(dir, h[:2])
	if e != nil {
		return nil, e
	}
	defer unix.Close(shard)
	fd, e := openLeaf(shard, h[2:])
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "evidence")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("open blob")
	}
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("blob is not regular")
	}
	if st.Size > maxBlobSize {
		return nil, errors.New("blob exceeds size limit")
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxBlobSize+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > maxBlobSize {
		return nil, errors.New("blob exceeds size limit")
	}
	return blob, nil
}

func openLeaf(parent int, name string) (int, error) {
	for {
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == unix.EINTR {
			continue
		}
		return fd, err
	}
}

func (r *casRoot) close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	fd := r.fd
	r.fd = -1
	return unix.Close(fd)
}
