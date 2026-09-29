//go:build unix

package newtransaction

import (
	"errors"
	"os"
	"syscall"
)

var errWouldBlock = errors.New("new transaction: lock is held")

// lockFile takes an exclusive advisory flock. The lock is released when the
// file is closed, including when the process dies, so a crashed writer never
// wedges recovery.
func lockFile(f *os.File, wait bool) error {
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return errWouldBlock
		}
		return err
	}
	return nil
}

// singleLink reports whether info describes a file with exactly one hard
// link. CAS blobs are private copies; a second link would let another path
// alias (and later mutate) recovery evidence.
func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
