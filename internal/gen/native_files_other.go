//go:build !darwin && !linux

package gen

import (
	"io/fs"
)

func nativeSingleLink(fs.FileInfo) bool         { return false }
func nativeFileID(fs.FileInfo) (uint64, uint64) { return 0, 0 }
