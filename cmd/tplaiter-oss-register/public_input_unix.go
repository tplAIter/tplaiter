//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// Open without waiting for a FIFO writer, then validate this exact descriptor
// in readPublicInput. A pathname pre-stat cannot establish its file type.
func openPublicInput(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
