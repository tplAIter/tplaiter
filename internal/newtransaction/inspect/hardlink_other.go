//go:build !unix

package inspect

import "os"

func singleLink(os.FileInfo) bool { return false }
