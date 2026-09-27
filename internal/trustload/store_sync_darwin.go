//go:build darwin

package trustload

import "golang.org/x/sys/unix"

func storePlatformAvailable() bool { return true }

func storeFilesystemSupported(fd int) bool {
	var st unix.Statfs_t
	if unix.Fstatfs(fd, &st) != nil {
		return false
	}
	name := string(st.Fstypename[:])
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}
	return name == "apfs"
}

func syncStoreFile(fd int) error {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0)
	return err
}

func syncStoreDirectory(fd int) error { return unix.Fsync(fd) }

func storeRenameNoReplace(rootFD int, pending, active string) error {
	return unix.RenameatxNp(rootFD, pending, rootFD, active, unix.RENAME_EXCL)
}
