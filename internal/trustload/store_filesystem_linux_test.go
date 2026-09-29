//go:build linux

package trustload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLinuxFilesystemFamilyAllowlist pins the closed allowlist: only the
// natively proven families are admitted, and every other known family stays
// fail-closed.
func TestLinuxFilesystemFamilyAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic int64
		want  bool
	}{
		{"ext4", linuxExt4SuperMagic, true},
		{"overlayfs", linuxOverlayfsMagic, true},
		{"tmpfs", linuxTmpfsMagic, false},
		{"btrfs", linuxBtrfsSuperMagic, false},
		{"xfs", linuxXFSSuperMagic, false},
		{"nfs", linuxNFSSuperMagic, false},
		{"fuse", linuxFUSESuperMagic, false},
		{"9p", linuxV9FSMagic, false},
		{"zero", 0, false},
		{"sign-extended-ext4", int64(-1)<<32 | linuxExt4SuperMagic, true},
	} {
		if got := linuxFilesystemFamilyAdmitted(tc.magic); got != tc.want {
			t.Errorf("%s (0x%x): admitted=%v, want %v", tc.name, tc.magic, got, tc.want)
		}
	}
}

// TestLinuxStoreTestRootIsProvenFamily records which filesystem family the
// native store matrix actually ran on, so a CI log shows the evidence, and
// fails if the matrix silently ran on an unadmitted family (in which case
// every store test would have exercised only the unavailable route).
func TestLinuxStoreTestRootIsProvenFamily(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		t.Fatal(err)
	}
	t.Logf("store test root %s: statfs f_type=0x%x", dir, uint32(st.Type))
	if !storeFilesystemSupported(fd) {
		t.Fatalf("TMPDIR %s is on an unadmitted filesystem (f_type=0x%x); run the store matrix on ext4 or overlayfs", dir, uint32(st.Type))
	}
}

// TestLinuxStoreRefusesTmpfsRoot proves the real (not injected) preflight on
// an unadmitted family: enrollment on tmpfs returns the typed code and creates
// nothing. /dev/shm is tmpfs on standard Linux and container hosts.
func TestLinuxStoreRefusesTmpfsRoot(t *testing.T) {
	const shm = "/dev/shm"
	var st unix.Statfs_t
	if err := unix.Statfs(shm, &st); err != nil || uint32(st.Type) != linuxTmpfsMagic || unix.Access(shm, unix.W_OK) != nil {
		t.Skip("environment: no writable tmpfs at /dev/shm to exercise the unadmitted-family route")
	}
	base, err := os.MkdirTemp(shm, "tplaiter-store-tmpfs-")
	if err != nil {
		t.Skip("environment: cannot create a directory on /dev/shm: " + err.Error())
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root := filepath.Join(base, "store")
	for _, mode := range []storeMode{storeEnroll, storeRead, storeRefresh, storeRecover} {
		lease, err := openRootLease(context.Background(), root, mode)
		if lease != nil {
			_ = lease.Close()
			t.Fatalf("mode %v: tmpfs root lease granted", mode)
		}
		if mode == storeEnroll && !errors.Is(err, ErrStoreFilesystemUnsupported) {
			t.Fatalf("enroll on tmpfs err=%v, want TRUST_STORE_FILESYSTEM_UNSUPPORTED", err)
		}
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("mode %v on tmpfs err=%v, want provenance-unavailable family", mode, err)
		}
		if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
			t.Fatalf("mode %v: unadmitted filesystem created the store root: %v", mode, statErr)
		}
	}
	// An existing private root on tmpfs is refused after the no-follow walk,
	// before any lock or SQLite binding is taken.
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []storeMode{storeRead, storeRefresh, storeRecover} {
		lease, err := openRootLease(context.Background(), root, mode)
		if lease != nil {
			_ = lease.Close()
			t.Fatalf("mode %v: existing tmpfs root lease granted", mode)
		}
		if !errors.Is(err, ErrStoreFilesystemUnsupported) {
			t.Fatalf("mode %v existing tmpfs root err=%v, want TRUST_STORE_FILESYSTEM_UNSUPPORTED", mode, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused tmpfs root was written: entries=%v err=%v", entries, err)
	}
}

// TestLinuxStoreRenameNoReplace proves the activation primitive on the native
// filesystem: it publishes atomically when the target is absent and refuses,
// without mutating either name, when the target exists.
func TestLinuxStoreRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	write("pending", "next")
	write("active", "current")
	if err := storeRenameNoReplace(fd, "pending", "active"); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("rename over existing active err=%v, want EEXIST", err)
	}
	if read("active") != "current" || read("pending") != "next" {
		t.Fatal("refused no-replace rename mutated the namespace")
	}
	if err := os.Remove(filepath.Join(dir, "active")); err != nil {
		t.Fatal(err)
	}
	if err := storeRenameNoReplace(fd, "pending", "active"); err != nil {
		t.Fatalf("no-replace publish: %v", err)
	}
	if err := syncStoreDirectory(fd); err != nil {
		t.Fatalf("directory fsync: %v", err)
	}
	if read("active") != "next" {
		t.Fatal("published marker has wrong bytes")
	}
	if _, err := os.Lstat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		t.Fatalf("pending name survived publish: %v", err)
	}
}

// TestLinuxStoreRootLockExcludesWriters proves flock(2) semantics on the
// native root: a writable lease is exclusive against a second writer and a
// reader, and readers share.
func TestLinuxStoreRootLockExcludesWriters(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	enroll, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := openRootLease(context.Background(), root, storeRefresh); other != nil || !errors.Is(err, ErrRefreshConflict) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatalf("second writer err=%v, want refresh conflict", err)
	}
	if reader, err := openRootLease(context.Background(), root, storeRead); reader != nil || !errors.Is(err, ErrPending) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("reader during writer err=%v, want pending", err)
	}
	if err := enroll.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatalf("shared reader: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if writer, err := openRootLease(context.Background(), root, storeRefresh); writer != nil || !errors.Is(err, ErrRefreshConflict) {
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatalf("writer during reader err=%v, want refresh conflict", err)
	}
}
