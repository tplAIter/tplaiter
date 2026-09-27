//go:build darwin || linux

package trustload

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func secureReadFile(path string, limit int) ([]byte, error) {
	if !absolutePath(path) {
		return nil, ErrPinMismatch
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPinMismatch
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, ErrPinMismatch
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(next)
			return nil, ErrPinMismatch
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > int64(limit) {
		return nil, ErrPinMismatch
	}
	f := os.NewFile(uintptr(fd), "trustload")
	if f == nil {
		return nil, ErrPinMismatch
	}
	closeFD = false
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrPinMismatch
	}
	return b, nil
}
