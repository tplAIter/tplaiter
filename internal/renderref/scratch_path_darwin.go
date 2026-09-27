//go:build darwin

package renderref

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// enginePathForFD derives the engine target only from the still-held private
// child descriptor. F_GETPATH is needed because Darwin does not expose a
// directory fd through /dev/fd as a path usable by the existing engine.
func enginePathForFD(fd int) (string, error) {
	var raw [1024]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&raw[0])))
	if errno != 0 {
		return "", errno
	}
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	if n == 0 {
		return "", errors.New("renderref: empty held scratch path")
	}
	return string(raw[:n]), nil
}
