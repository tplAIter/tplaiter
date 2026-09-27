//go:build darwin || linux

package trustload

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// objectRoot owns a descriptor for one installed object-store root. Retaining
// the descriptor prevents a later pathname rename or real-directory swap from
// redirecting a verified source read.
type objectRoot struct {
	fd       int
	dev, ino uint64
}

func openObjectRoot(path string) (*objectRoot, error) {
	if !absolutePath(path) {
		return nil, ErrConfigInvalid
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Close(fd)
			return nil, ErrProvenanceUnavailable
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(next)
			return nil, ErrProvenanceUnavailable
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, ErrProvenanceUnavailable
	}
	return &objectRoot{fd: fd, dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

func (r *objectRoot) read(name string) ([]byte, error) {
	if r == nil || r.fd < 0 {
		return nil, ErrProvenanceUnavailable
	}
	fd, err := unix.Openat(r.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	file := os.NewFile(uintptr(fd), "trustload-object")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrProvenanceUnavailable
	}
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 || st.Size > maxRawObjectData+maxRawObjectHeader {
		return nil, ErrProvenanceUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxRawObjectData+maxRawObjectHeader)+1))
	if err != nil || len(raw) > maxRawObjectData+maxRawObjectHeader {
		return nil, ErrProvenanceUnavailable
	}
	return raw, nil
}

func (r *objectRoot) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	fd := r.fd
	r.fd = -1
	if err := unix.Close(fd); err != nil {
		return ErrProvenanceUnavailable
	}
	return nil
}
