//go:build !linux && !darwin

package updateplan

import "os"

func updateFileID(os.FileInfo) (uint64, uint64) { return 0, 0 }
func updateSingleLink(os.FileInfo) bool         { return false }
