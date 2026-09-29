//go:build linux

package trustload

import "golang.org/x/sys/unix"

// Linux filesystem magic numbers (statfs(2) f_type) for the families whose
// locking, durability, no-replace rename and crash/reload behavior has been
// exercised natively by the store test matrix (see
// docs/adr/ADR-006-linux-trust-store.md). Every other family, including
// tmpfs (no durability), NFS, FUSE (including virtiofs) and 9p (no reliable
// flock or no-replace rename), and btrfs/xfs (not yet proven), stays
// fail-closed.
const (
	linuxExt4SuperMagic  = 0xEF53     // ext2/ext3/ext4 share one magic
	linuxOverlayfsMagic  = 0x794c7630 // overlayfs (container root filesystems)
	linuxTmpfsMagic      = 0x01021994 // documented for tests; never admitted
	linuxBtrfsSuperMagic = 0x9123683E // not proven
	linuxXFSSuperMagic   = 0x58465342 // not proven
	linuxNFSSuperMagic   = 0x6969     // network filesystem; never admitted
	linuxFUSESuperMagic  = 0x65735546 // userspace filesystem; never admitted
	linuxV9FSMagic       = 0x01021997 // 9p host shares; never admitted
)

func storePlatformAvailable() bool { return true }

// storeFilesystemSupported admits only the proven filesystem families. The
// decision is made on the held directory descriptor, never on a path, so a
// concurrent mount or rename cannot redirect the predicate.
func storeFilesystemSupported(fd int) bool {
	var st unix.Statfs_t
	if unix.Fstatfs(fd, &st) != nil {
		return false
	}
	return linuxFilesystemFamilyAdmitted(int64(st.Type))
}

// linuxFilesystemFamilyAdmitted is the closed allowlist, separated from the
// syscall so the unsupported families can be asserted deterministically.
func linuxFilesystemFamilyAdmitted(magic int64) bool {
	// f_type is a 32-bit magic in a wider signed word; compare the low bits.
	switch magic & 0xffffffff {
	case linuxExt4SuperMagic, linuxOverlayfsMagic:
		return true
	default:
		return false
	}
}

// fsync on ext4 and overlayfs (whose upper layer is itself a local
// filesystem) issues the device cache flush required for durability; Linux
// has no F_FULLFSYNC equivalent and needs none.
func syncStoreFile(fd int) error      { return unix.Fsync(fd) }
func syncStoreDirectory(fd int) error { return unix.Fsync(fd) }

// storeRenameNoReplace publishes the pending marker atomically and refuses to
// replace an existing active marker. renameat2(RENAME_NOREPLACE) is supported
// by both admitted families; a kernel or filesystem without it reports
// EINVAL/ENOSYS and the activation fails closed. There is deliberately no
// plain renameat fallback, because that would silently allow replacement.
func storeRenameNoReplace(rootFD int, pending, active string) error {
	return unix.Renameat2(rootFD, pending, rootFD, active, unix.RENAME_NOREPLACE)
}
