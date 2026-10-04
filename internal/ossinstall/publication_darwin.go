//go:build darwin

package ossinstall

import "golang.org/x/sys/unix"

func renameInstallationExclusive(parentFD int, stage, root string) error {
	return unix.RenameatxNp(parentFD, stage, parentFD, root, unix.RENAME_EXCL)
}
