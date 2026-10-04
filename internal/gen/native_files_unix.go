//go:build darwin || linux

package gen

import (
	"io/fs"
	"syscall"
)

func nativeSingleLink(info fs.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}

func nativeFileID(info fs.FileInfo) (uint64, uint64) {
	if info == nil {
		return 0, 0
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return nativeDeviceID(s.Dev), s.Ino
}
