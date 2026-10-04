//go:build linux

package engine

import "golang.org/x/sys/unix"

func exchangeAt(a int, x string, b int, y string) error {
	return unix.Renameat2(a, x, b, y, unix.RENAME_EXCHANGE)
}

func exclusiveRenameAt(a int, x string, b int, y string) error {
	return unix.Renameat2(a, x, b, y, unix.RENAME_NOREPLACE)
}
