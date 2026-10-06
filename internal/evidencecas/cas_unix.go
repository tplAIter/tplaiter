//go:build darwin || linux

package evidencecas

import (
	"context"
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

// readBounded keeps the root, namespace, shard and leaf descriptors held while
// observing size and reading. Identity rereads reject replacement at any step.
func (r *casRoot) readBounded(ctx context.Context, h string, maximumBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := openDir(r.fd, "sha256")
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	shard, err := openDir(dir, h[:2])
	if err != nil {
		return nil, err
	}
	defer unix.Close(shard)
	fd, err := openLeaf(shard, h[2:])
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "bounded-evidence")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("open blob")
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var leaf unix.Stat_t
	if err := unix.Fstat(fd, &leaf); err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || leaf.Nlink != 1 {
		return nil, errors.New("blob is not a single-link regular file")
	}
	// Validate the observed size and caller cap BEFORE allocating body storage.
	if before.Size() < 0 || before.Size() > maxBlobSize || before.Size() > maximumBytes {
		return nil, ErrBoundExceeded
	}
	blob, err := readBoundedBytes(ctx, f, before.Size())
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrBlobChanged
	}
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return nil, err
	}
	if held.Dev != leaf.Dev || held.Ino != leaf.Ino || held.Mode != leaf.Mode || held.Nlink != leaf.Nlink || held.Size != leaf.Size {
		return nil, ErrBlobChanged
	}
	if err := boundedPathIdentity(shard, h[2:], fd); err != nil {
		return nil, err
	}
	if err := boundedPathIdentity(dir, h[:2], shard); err != nil {
		return nil, err
	}
	if err := boundedPathIdentity(r.fd, "sha256", dir); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return blob, nil
}

func boundedPathIdentity(parent int, name string, held int) error {
	var actual, pinned unix.Stat_t
	if err := unix.Fstat(held, &pinned); err != nil {
		return err
	}
	if err := unix.Fstatat(parent, name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if actual.Dev != pinned.Dev || actual.Ino != pinned.Ino || actual.Mode != pinned.Mode || actual.Nlink != pinned.Nlink || actual.Size != pinned.Size {
		return ErrBlobChanged
	}
	return nil
}

// readBoundedBytes has a deterministic I/O seam for growth, truncation and
// mid-read cancellation. It allocates exactly observed+1 bytes, never ReadAll.
func readBoundedBytes(ctx context.Context, reader io.Reader, observed int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if observed < 0 || observed > maxBlobSize {
		return nil, ErrBoundExceeded
	}
	buf := make([]byte, int(observed)+1)
	n := 0
	for n < len(buf) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := n + 32*1024
		if end > len(buf) {
			end = len(buf)
		}
		read, err := reader.Read(buf[n:end])
		n += read
		if cause := ctx.Err(); cause != nil {
			return nil, cause
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return nil, io.ErrNoProgress
		}
	}
	if int64(n) != observed {
		return nil, ErrBlobChanged
	}
	return buf[:n:n], nil
}
