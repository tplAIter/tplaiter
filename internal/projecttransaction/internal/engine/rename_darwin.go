//go:build darwin

package engine

import "golang.org/x/sys/unix"

func exchangeAt(a int, x string, b int, y string) error {
	return unix.RenameatxNp(a, x, b, y, unix.RENAME_SWAP)
}

func exclusiveRenameAt(a int, x string, b int, y string) error {
	return unix.RenameatxNp(a, x, b, y, unix.RENAME_EXCL)
}
