//go:build darwin

package mcpsrv

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pathFromFD resolves the current path of an open descriptor through
// fcntl(F_GETPATH), so the held stage is located by its inode rather than by a
// caller-supplied name.
func pathFromFD(fd int) (string, error) {
	var raw [1024]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&raw[0]))) //nolint:staticcheck // x/sys/unix has no F_GETPATH wrapper
	if errno != 0 {
		return "", errno
	}
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	if n == 0 {
		return "", errors.New("empty path")
	}
	return string(raw[:n]), nil
}
