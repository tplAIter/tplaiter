//go:build linux || darwin

package updateplan

import (
	"os"
	"syscall"
)

func updateFileID(info os.FileInfo) (uint64, uint64) {
	if info == nil {
		return 0, 0
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Dev < 0 {
		return 0, 0
	}
	return uint64(s.Dev), s.Ino
}

func updateSingleLink(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}
