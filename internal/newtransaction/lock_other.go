//go:build !unix

package newtransaction

import (
	"errors"
	"os"
)

var errWouldBlock = errors.New("new transaction: lock is held")

// lockFile is unsupported off unix: the global transaction requires flock
// semantics (Windows support is deferred).
func lockFile(*os.File, bool) error {
	return errors.New("new transaction: file locking is unsupported on this platform")
}

func singleLink(os.FileInfo) bool { return false }
