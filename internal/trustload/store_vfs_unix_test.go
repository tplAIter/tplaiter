//go:build darwin || linux

package trustload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreVFSActualSQLiteTransaction(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE proof (v INTEGER); INSERT INTO proof VALUES (7)"); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName)); err != nil {
		t.Fatal(err)
	}
	reader, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	readBinding, err := openSQLBinding(context.Background(), reader, storeRead)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	var v int
	if err := readBinding.conn.QueryRowContext(context.Background(), "SELECT v FROM proof").Scan(&v); err != nil || v != 7 {
		t.Fatalf("read = %d, %v", v, err)
	}
	if _, err := readBinding.conn.ExecContext(context.Background(), "INSERT INTO proof VALUES (8)"); err == nil {
		t.Fatal("readonly VFS accepted a write")
	}
	if _, err := readBinding.conn.ExecContext(context.Background(), "ATTACH DATABASE ':memory:' AS foreign_db"); err == nil {
		t.Fatal("retained connection accepted ATTACH")
	}
	if err := readBinding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreVFSRejectsForeignCallbackWithoutOpeningLeaf(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	foreign, err := libc.CString("/tplaiter-store/foreign/bootstrap.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, foreign)
	pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if pfile == 0 {
		t.Fatal("malloc file")
	}
	defer libc.Xfree(v.tls, pfile)
	if rc := storeVFSOpen(v.tls, v.vfs, foreign, pfile, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); rc != sqlite3.SQLITE_CANTOPEN {
		t.Fatalf("foreign rc=%d", rc)
	}
	if got := (*vfsContext)(libcPtr(v.ctx)).deniedOpens; got != 1 {
		t.Fatalf("denied=%d", got)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign callback opened leaf: %v", err)
	}
}

func TestReadBindingRejectsExistingSidecars(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE sidecar_proof (v INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{storeDBName + "-journal", storeDBName + "-wal", storeDBName + "-shm"} {
		if err := os.WriteFile(filepath.Join(root, sidecar), []byte("hostile"), 0o600); err != nil {
			t.Fatal(err)
		}
		reader, err := openRootLease(context.Background(), root, storeRead)
		if err != nil {
			t.Fatal(err)
		}
		_, got := openSQLBinding(context.Background(), reader, storeRead)
		_ = reader.Close()
		if !errors.Is(got, ErrPending) {
			t.Fatalf("%s: %v", sidecar, got)
		}
		if err := os.Remove(filepath.Join(root, sidecar)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreVFSInjectedIOFaultsReturnSQLiteErrors(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := os.WriteFile(filepath.Join(root, storeDBName), []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := newStoreVFS(lease, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	name, err := libc.CString(v.main)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, name)
	pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if pfile == 0 {
		t.Fatal("malloc file")
	}
	defer libc.Xfree(v.tls, pfile)
	if rc := storeVFSOpen(v.tls, v.vfs, name, pfile, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); rc != sqlite3.SQLITE_OK {
		t.Fatalf("open rc=%d", rc)
	}
	ctx := (*vfsContext)(libcPtr(v.ctx))
	buf := libc.Xmalloc(v.tls, 8)
	if buf == 0 {
		t.Fatal("malloc buffer")
	}
	defer libc.Xfree(v.tls, buf)
	for _, tc := range []struct {
		fault int64
		call  func() int32
		want  int32
	}{
		{storeFaultRead, func() int32 { return storeFileRead(v.tls, pfile, buf, 1, 0) }, sqlite3.SQLITE_IOERR_READ},
		{storeFaultWrite, func() int32 { return storeFileWrite(v.tls, pfile, buf, 1, 0) }, sqlite3.SQLITE_IOERR_WRITE},
		{storeFaultSync, func() int32 { return storeFileSync(v.tls, pfile, 0) }, sqlite3.SQLITE_IOERR_FSYNC},
	} {
		ctx.fault = tc.fault
		if got := tc.call(); got != tc.want {
			t.Fatalf("fault %d: got %d want %d", tc.fault, got, tc.want)
		}
	}
	ctx.fault = storeFaultNone
	if got := storeFileRead(v.tls, pfile, 0, 0, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("zero-length nil read=%d", got)
	}
	if got := storeFileWrite(v.tls, pfile, 0, 0, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("zero-length nil write=%d", got)
	}
	if got := storeFileRead(v.tls, pfile, 0, 1, 0); got != sqlite3.SQLITE_IOERR_READ {
		t.Fatalf("nil read buffer=%d", got)
	}
	if got := storeFileWrite(v.tls, pfile, 0, 1, 0); got != sqlite3.SQLITE_IOERR_WRITE {
		t.Fatalf("nil write buffer=%d", got)
	}
	if got := storeFileRead(v.tls, pfile, buf, 1, sqlite3.Tsqlite3_int64(^uint64(0)>>1)); got != sqlite3.SQLITE_IOERR_READ {
		t.Fatalf("overflow read=%d", got)
	}
	if got := storeFileWrite(v.tls, pfile, buf, 1, sqlite3.Tsqlite3_int64(^uint64(0)>>1)); got != sqlite3.SQLITE_IOERR_WRITE {
		t.Fatalf("overflow write=%d", got)
	}
	oldPread := storePread
	reads := 0
	storePread = func(fd int, b []byte, off int64) (int, error) {
		reads++
		if reads == 1 {
			return -1, unix.EINTR
		}
		return oldPread(fd, b, off)
	}
	defer func() { storePread = oldPread }()
	if got := storeFileRead(v.tls, pfile, buf, 8, 0); got != sqlite3.SQLITE_IOERR_SHORT_READ {
		t.Fatalf("EINTR short read=%d", got)
	}
	if reads < 2 {
		t.Fatal("Pread EINTR was not retried")
	}
	gotBytes := unsafe.Slice((*byte)(libcPtr(buf)), 8)
	if gotBytes[6] != 0 || gotBytes[7] != 0 {
		t.Fatalf("short-read tail was not zero-filled: %v", gotBytes)
	}
	oldPwrite := storePwrite
	writes := 0
	storePwrite = func(fd int, b []byte, off int64) (int, error) {
		writes++
		if writes == 1 {
			return 0, unix.EINTR
		}
		return oldPwrite(fd, b, off)
	}
	defer func() { storePwrite = oldPwrite }()
	*(*byte)(libcPtr(buf)) = 'z'
	if got := storeFileWrite(v.tls, pfile, buf, 1, 0); got != sqlite3.SQLITE_OK || writes < 2 {
		t.Fatalf("EINTR write rc=%d writes=%d", got, writes)
	}
	storePwrite = func(int, []byte, int64) (int, error) { return 2, nil }
	if got := storeFileWrite(v.tls, pfile, buf, 1, 0); got != sqlite3.SQLITE_IOERR_WRITE {
		t.Fatalf("out-of-range partial write=%d", got)
	}
	ctx.fault = storeFaultClose
	if got := storeFileClose(v.tls, pfile); got != sqlite3.SQLITE_IOERR_CLOSE {
		t.Fatalf("close got %d", got)
	}
	ctx.fault = storeFaultNone
}

func TestStoreVFSDeleteMissingJournalAndPoisonsEntryDrift(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	v, err := newStoreVFS(lease, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	journalName, err := libc.CString(v.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, journalName)
	if got := storeVFSDelete(v.tls, v.vfs, journalName, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("missing journal delete=%d", got)
	}
	if err := os.WriteFile(filepath.Join(root, storeDBName), []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	mainName, err := libc.CString(v.main)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, mainName)
	pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if pfile == 0 {
		t.Fatal("malloc file")
	}
	defer libc.Xfree(v.tls, pfile)
	if got := storeVFSOpen(v.tls, v.vfs, mainName, pfile, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("open=%d", got)
	}
	defer storeFileClose(v.tls, pfile)
	main := filepath.Join(root, storeDBName)
	saved := main + ".saved"
	if err := os.Rename(main, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf := libc.Xmalloc(v.tls, 1)
	if buf == 0 {
		t.Fatal("malloc buffer")
	}
	defer libc.Xfree(v.tls, buf)
	if got := storeFileRead(v.tls, pfile, buf, 1, 0); got != sqlite3.SQLITE_IOERR_READ {
		t.Fatalf("replacement read=%d", got)
	}
	if err := os.Remove(main); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, main); err != nil {
		t.Fatal(err)
	}
	if got := storeFileRead(v.tls, pfile, buf, 1, 0); got != sqlite3.SQLITE_IOERR_READ {
		t.Fatalf("poisoned restored read=%d", got)
	}
}

func TestStoreVFSDeleteRejectsSubstitutedJournal(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	v, err := newStoreVFS(lease, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	name, err := libc.CString(v.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, name)
	journal := filepath.Join(root, storeDBName+"-journal")
	out := filepath.Join(base, "outside")
	if err := os.WriteFile(out, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		make func() error
	}{
		{"symlink", func() error { return os.Symlink(out, journal) }},
		{"fifo", func() error { return unix.Mkfifo(journal, 0o600) }},
		{"hardlink", func() error {
			if err := os.WriteFile(journal+"-source", []byte("x"), 0o600); err != nil {
				return err
			}
			return os.Link(journal+"-source", journal)
		}},
	}
	for _, tc := range cases {
		if err := tc.make(); err != nil {
			t.Fatalf("%s setup: %v", tc.name, err)
		}
		if got := storeVFSDelete(v.tls, v.vfs, name, 0); got != sqlite3.SQLITE_IOERR_DELETE {
			t.Fatalf("%s rc=%d", tc.name, got)
		}
		if err := lease.deleteJournal(); err == nil {
			t.Fatalf("%s root delete succeeded", tc.name)
		}
		if _, err := os.Lstat(journal); err != nil {
			t.Fatalf("%s was deleted: %v", tc.name, err)
		}
		if err := os.Remove(journal); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(journal + "-source")
	}
}

func TestStoreVFSBoundedWorkloadAndTeardown(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	vfsName := binding.vfs.name
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE workload (v BLOB)"); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 16<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	for i := 0; i < 4; i++ {
		if _, err := binding.conn.ExecContext(context.Background(), "INSERT INTO workload VALUES(?)", payload); err != nil {
			t.Fatalf("blob %d: %v", i, err)
		}
	}
	runtime.GC()
	var count int
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM workload").Scan(&count); err != nil || count != 4 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	rootFD := lease.fd
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err == nil {
		t.Fatal("root fd remained open")
	}
	tls := libc.NewTLS()
	defer tls.Close()
	name, err := libc.CString(vfsName)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, name)
	if got := sqlite3.Xsqlite3_vfs_find(tls, name); got != 0 {
		t.Fatalf("VFS remained registered: %#x", got)
	}
}

func TestStoreVFSCrashRecoveryKeepsCompleteHead(t *testing.T) {
	if root := os.Getenv("TRUSTLOAD_TEST_CRASH_ROOT"); root != "" {
		lease, err := openRootLease(context.Background(), root, storeRefresh)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := openSQLBinding(context.Background(), lease, storeRefresh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), "UPDATE crash_proof SET v=2"); err != nil {
			t.Fatal(err)
		}
		if os.Getenv("TRUSTLOAD_TEST_CRASH_COMMIT") != "" {
			if _, err := binding.conn.ExecContext(context.Background(), "COMMIT"); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(os.Getenv("TRUSTLOAD_TEST_CRASH_READY"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE crash_proof (v INTEGER); INSERT INTO crash_proof VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(base, "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreVFSCrashRecoveryKeepsCompleteHead$")
	cmd.Env = append(os.Environ(), "TRUSTLOAD_TEST_CRASH_ROOT="+root, "TRUSTLOAD_TEST_CRASH_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach uncommitted journal state")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	recovery, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := openSQLBinding(context.Background(), recovery, storeRecover)
	if err != nil {
		_ = recovery.Close()
		t.Fatal(err)
	}
	var v int
	if err := recovered.conn.QueryRowContext(context.Background(), "SELECT v FROM crash_proof").Scan(&v); err != nil || v != 1 {
		t.Fatalf("recovered value=%d err=%v", v, err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
	// A process death after a successful COMMIT must preserve the complete new
	// head; use a new root so the old-head recovery's retained journal cannot
	// affect this independent durability boundary.
	committedRoot := filepath.Join(base, "store-committed")
	seed, err := openRootLease(context.Background(), committedRoot, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	seedBinding, err := openSQLBinding(context.Background(), seed, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE crash_proof (v INTEGER); INSERT INTO crash_proof VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	if err := seedBinding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(ready)
	cmd = exec.Command(os.Args[0], "-test.run=^TestStoreVFSCrashRecoveryKeepsCompleteHead$")
	cmd.Env = append(os.Environ(), "TRUSTLOAD_TEST_CRASH_ROOT="+committedRoot, "TRUSTLOAD_TEST_CRASH_READY="+ready, "TRUSTLOAD_TEST_CRASH_COMMIT=1")
	var childLog bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childLog, &childLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("committed child did not reach ready state: %s", childLog.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	recovery, err = openRootLease(context.Background(), committedRoot, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err = openSQLBinding(context.Background(), recovery, storeRecover)
	if err != nil {
		_ = recovery.Close()
		t.Fatal(err)
	}
	if err := recovered.conn.QueryRowContext(context.Background(), "SELECT v FROM crash_proof").Scan(&v); err != nil || v != 2 {
		t.Fatalf("committed recovered value=%d err=%v", v, err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
}
