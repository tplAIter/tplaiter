//go:build linux

package ossinstall

import "golang.org/x/sys/unix"

func renameInstallationExclusive(parentFD int, stage, root string) error {
	return unix.Renameat2(parentFD, stage, parentFD, root, unix.RENAME_NOREPLACE)
}
