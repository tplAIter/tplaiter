//go:build linux

package trustload

import "golang.org/x/sys/unix"

// Linux remains unavailable until a native filesystem/lock/durability proof
// is recorded for a closed filesystem family. Cross-compilation never enables
// a store adapter.
func storePlatformAvailable() bool      { return false }
func storeFilesystemSupported(int) bool { return false }
func syncStoreFile(fd int) error        { return unix.Fsync(fd) }
func syncStoreDirectory(fd int) error   { return unix.Fsync(fd) }

// Linux has no admitted native adapter proof. In particular, do not turn the
// availability stub into a Renameat fallback: activation must be no-replace.
func storeRenameNoReplace(int, string, string) error { return ErrProvenanceUnavailable }
