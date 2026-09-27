//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreNamespaceNS004ReadOnlyStartupSidecars(t *testing.T) {
	if root := os.Getenv("TPLAITER_NS004_HOT_ROOT"); root != "" {
		lease, err := openRootLease(context.Background(), root, storeRefresh)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := openSQLBinding(context.Background(), lease, storeRefresh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE; UPDATE ns004 SET v=2"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("TPLAITER_NS004_HOT_READY"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		release := os.NewFile(uintptr(3), "ns004-release")
		if release == nil {
			t.Fatal("release rendezvous fd missing")
		}
		_, _ = io.Copy(io.Discard, release)
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	seed, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	seedBinding, err := openSQLBinding(context.Background(), seed, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE ns004(v INTEGER); INSERT INTO ns004 VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	if err := seedBinding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	ready := filepath.Join(base, "hot-ready")
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseWriter.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreNamespaceNS004ReadOnlyStartupSidecars$")
	cmd.Env = append(os.Environ(), "TPLAITER_NS004_HOT_ROOT="+root, "TPLAITER_NS004_HOT_READY="+ready)
	cmd.ExtraFiles = []*os.File{releaseReader}
	if err := cmd.Start(); err != nil {
		releaseReader.Close()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			releaseReader.Close()
			t.Fatal("hot-journal child did not reach rendezvous")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		releaseReader.Close()
		t.Fatal(err)
	}
	_ = cmd.Wait()
	releaseReader.Close()
	hotJournal := filepath.Join(root, storeDBName+"-journal")
	hotBytes, err := os.ReadFile(hotJournal)
	if err != nil || len(hotBytes) == 0 {
		t.Fatalf("real hot journal missing or empty: %v", err)
	}
	ns004AssertReaderRejectsSidecar(t, root, hotJournal, hotBytes)

	if err := os.Remove(hotJournal); err != nil {
		t.Fatal(err)
	}
	coldBytes := append([]byte(nil), hotBytes...)
	if len(coldBytes) < 8 {
		t.Fatalf("real journal too short for cold header: %d", len(coldBytes))
	}
	// A separate SQLite PERSIST journal is a real cold vector: SQLite retains
	// the journal body but clears its magic after the transaction commits.
	coldBytes = ns004RealColdJournal(t, base)
	if reflect.DeepEqual(coldBytes, hotBytes) {
		t.Fatal("cold journal vector is byte-identical to hot journal")
	}
	if err := os.WriteFile(hotJournal, coldBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ns004AssertReaderRejectsSidecar(t, root, hotJournal, coldBytes)

	walSidecars := ns004RealWALSidecars(t, base)
	for _, name := range []string{storeDBName + "-wal", storeDBName + "-shm"} {
		path := filepath.Join(root, name)
		bytes := walSidecars[name]
		if err := os.WriteFile(path, bytes, 0o600); err != nil {
			t.Fatal(err)
		}
		ns004AssertReaderRejectsSidecar(t, root, path, bytes)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	zero := filepath.Join(root, storeDBName+"-journal")
	if err := os.WriteFile(zero, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ns004AssertReaderRejectsSidecar(t, root, zero, []byte{})

	if err := os.Remove(zero); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, pendingMarkerName)
	if err := os.WriteFile(marker, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := openRootLease(context.Background(), root, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := openSQLBinding(context.Background(), ex, storeRead)
	if err != nil {
		t.Fatal("same-EX pending verification: ", err)
	}
	if err := verification.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ex.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	inserted := filepath.Join(root, storeDBName+"-journal")
	proof := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
	ctx = context.WithValue(ctx, storeSetupFaultKey{}, storeSetupFault{
		beforeReaderPublication: func() {
			if err := os.WriteFile(inserted, []byte("inserted-after-precheck"), 0o600); err != nil {
				t.Fatalf("insert sidecar after precheck: %v", err)
			}
		},
	})
	if binding, got := openSQLBinding(ctx, reader, storeRead); binding != nil || !errors.Is(got, ErrPending) {
		t.Fatalf("post-precheck sidecar accepted: binding=%v err=%v", binding, got)
	}
	proof.mu.Lock()
	allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
	proof.mu.Unlock()
	if allocs != 0 || frees != 0 || registers != 0 || unregisters != 0 {
		t.Fatalf("post-precheck sidecar reached VFS: alloc/free=%d/%d register/unregister=%d/%d", allocs, frees, registers, unregisters)
	}
	if got, err := os.ReadFile(inserted); err != nil || string(got) != "inserted-after-precheck" {
		t.Fatalf("inserted sidecar changed: %v", err)
	}
}

func ns004RealWALSidecars(t *testing.T, base string) map[string][]byte {
	t.Helper()
	source := filepath.Join(base, "wal-source.sqlite")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("WAL setup mode=%q err=%v", mode, err)
	}
	if _, err := db.Exec("CREATE TABLE wal_source(v INTEGER); INSERT INTO wal_source VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{
		storeDBName + "-wal": source + "-wal",
		storeDBName + "-shm": source + "-shm",
	}
	result := make(map[string][]byte, len(paths))
	for name, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil || len(bytes) == 0 {
			t.Fatalf("real %s missing or empty: %v", name, err)
		}
		result[name] = bytes
	}
	return result
}

func ns004RealColdJournal(t *testing.T, base string) []byte {
	t.Helper()
	source := filepath.Join(base, "cold-source.sqlite")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode=PERSIST").Scan(&mode); err != nil || mode != "persist" {
		t.Fatalf("cold journal mode=%q err=%v", mode, err)
	}
	if _, err := db.Exec("CREATE TABLE cold_source(v INTEGER); INSERT INTO cold_source VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	path := source + "-journal"
	bytes, err := os.ReadFile(path)
	if err != nil || len(bytes) == 0 {
		t.Fatalf("real cold journal missing or empty: %v", err)
	}
	if len(bytes) < 8 || !reflect.DeepEqual(bytes[:8], make([]byte, 8)) {
		t.Fatalf("cold journal magic was not cleared: %x", bytes[:8])
	}
	return bytes
}

func ns004AssertReaderRejectsSidecar(t *testing.T, root, sidecar string, want []byte) {
	t.Helper()
	before := nsTreeSnapshot(t, root)
	reader, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	proof := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
	binding, got := openSQLBinding(ctx, reader, storeRead)
	if binding != nil || !errors.Is(got, ErrPending) {
		t.Fatalf("sidecar %s accepted: binding=%v err=%v", filepath.Base(sidecar), binding, got)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	proof.mu.Lock()
	allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
	proof.mu.Unlock()
	if allocs != 0 || frees != 0 || registers != 0 || unregisters != 0 {
		t.Fatalf("sidecar %s reached VFS: alloc/free=%d/%d register/unregister=%d/%d", filepath.Base(sidecar), allocs, frees, registers, unregisters)
	}
	if gotBytes, err := os.ReadFile(sidecar); err != nil || !reflect.DeepEqual(gotBytes, want) {
		t.Fatalf("sidecar %s changed: err=%v bytes=%q", filepath.Base(sidecar), err, gotBytes)
	}
	nsAssertTreeUnchanged(t, root, before)
}

func TestStoreBindingModeLeaseMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		leaseMode   storeMode
		requestMode storeMode
		deny        bool
	}{
		{storeRead, storeRead, false}, {storeRead, storeEnroll, true}, {storeRead, storeRefresh, true}, {storeRead, storeRecover, true},
		{storeEnroll, storeRead, false}, {storeEnroll, storeEnroll, false}, {storeEnroll, storeRefresh, false}, {storeEnroll, storeRecover, false},
		{storeRead, 0, true}, {storeRead, storeMode(99), true}, {storeEnroll, 0, true}, {storeEnroll, storeMode(99), true},
	} {
		t.Run(fmt.Sprintf("lease-%d-request-%d", tc.leaseMode, tc.requestMode), func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "store")
			seed, err := openRootLease(context.Background(), root, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			seedBinding, err := openSQLBinding(context.Background(), seed, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE mode_matrix(v INTEGER)"); err != nil {
				t.Fatal(err)
			}
			if err := seedBinding.Close(); err != nil {
				t.Fatal(err)
			}
			if tc.leaseMode == storeEnroll && tc.requestMode == storeEnroll {
				if err := os.Remove(filepath.Join(root, storeDBName)); err != nil {
					t.Fatal(err)
				}
			}
			var lease *rootLease
			if tc.leaseMode == storeEnroll {
				// Keep the exclusive lease created by enrollment. Reopening an
				// enrolled root would be rejected as a preexisting root.
				lease = seed
			} else {
				if err := seed.Close(); err != nil {
					t.Fatal(err)
				}
				lease, err = openRootLease(context.Background(), root, tc.leaseMode)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer lease.Close()
			proof := &storeProofObserver{}
			ctx := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
			binding, err := openSQLBinding(ctx, lease, tc.requestMode)
			if tc.deny {
				if err == nil || binding != nil {
					t.Fatal("SH lease accepted writable binding")
				}
				proof.mu.Lock()
				allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
				proof.mu.Unlock()
				if allocs != 0 || frees != 0 || registers != 0 || unregisters != 0 {
					t.Fatalf("denial allocated VFS: %d/%d %d/%d", allocs, frees, registers, unregisters)
				}
				return
			}
			if err != nil || binding == nil {
				t.Fatalf("legitimate mode rejected: %v", err)
			}
			if err := binding.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreBindingReaderSetupCancellationAndCleanup(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	phases := []string{"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF", "exec:PRAGMA query_only=ON", "query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema", "query:PRAGMA query_only"}
	for _, phase := range phases {
		for _, canceled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/cancel-%t", phase, canceled), func(t *testing.T) {
				base, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				root := filepath.Join(base, "store")
				seed, err := openRootLease(context.Background(), root, storeEnroll)
				if err != nil {
					t.Fatal(err)
				}
				seedBinding, err := openSQLBinding(context.Background(), seed, storeEnroll)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE reader_matrix(v INTEGER)"); err != nil {
					t.Fatal(err)
				}
				if err := seedBinding.Close(); err != nil {
					t.Fatal(err)
				}
				if err := seed.Close(); err != nil {
					t.Fatal(err)
				}
				lease, err := openRootLease(context.Background(), root, storeRead)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				proof := &storeProofObserver{}
				ctx := context.Background()
				var cancel context.CancelFunc
				if canceled {
					ctx, cancel = context.WithCancel(ctx)
				} else {
					ctx, cancel = context.WithCancel(ctx)
				}
				defer cancel()
				ctx = context.WithValue(ctx, storeProofObserverKey{}, proof)
				fault := storeSetupFault{phase: phase, err: errors.New("reader phase fault")}
				if canceled {
					fault.cancel = cancel
				}
				ctx = context.WithValue(ctx, storeSetupFaultKey{}, fault)
				binding, openErr := openSQLBinding(ctx, lease, storeRead)
				if openErr == nil || binding != nil {
					t.Fatalf("reader phase %s accepted failure", phase)
				}
				proof.mu.Lock()
				allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
				proof.mu.Unlock()
				if allocs != frees || registers != unregisters || allocs == 0 {
					t.Fatalf("reader cleanup %s: %d/%d %d/%d", phase, allocs, frees, registers, unregisters)
				}
				if !lease.valid() {
					t.Fatal("reader lease invalidated")
				}
			})
		}
	}
}

func TestStoreNamespaceForeignPathVector(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
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
	defer lease.Close()
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	type foreignVector struct {
		id   string
		path string
		null bool
	}
	vectors := []foreignVector{
		{"absolute", "/tplaiter/foreign.sqlite", false},
		{"traversal", v.main + "/../foreign", false},
		{"uri-memory", "file:foreign.sqlite?mode=memory", false},
		{"uri-unix-vfs", "file:/tmp/tplaiter-foreign.sqlite?vfs=unix", false},
		{"main-wal", v.main + "-wal", false},
		{"main-shm", v.main + "-shm", false},
		{"attached", v.main + "/attached.sqlite", false},
		{"superjournal", v.main + "-mj HIDDEN", false},
		{"temp-journal", v.main + "-temp-journal", false},
		{"subjournal", v.main + "-subjournal", false},
		{"marker-active", v.main + "/active", false},
		{"marker-pending", v.main + "/pending", false},
		{"null-temp", "", true},
	}
	openFlags := []struct {
		id    string
		flags int32
	}{
		{"readonly-main", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READONLY},
		{"readwrite-main", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE},
		{"create-main", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE | sqlite3.SQLITE_OPEN_CREATE},
		{"delete-on-close", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE | sqlite3.SQLITE_OPEN_DELETEONCLOSE},
		{"wal-mixture", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_WAL | sqlite3.SQLITE_OPEN_READWRITE},
		{"temp-mixture", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_TEMP_DB | sqlite3.SQLITE_OPEN_READWRITE},
		{"both-read-modes", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READONLY | sqlite3.SQLITE_OPEN_READWRITE},
		{"no-read-mode", sqlite3.SQLITE_OPEN_MAIN_DB},
	}
	for _, vector := range vectors {
		if vector.null {
			t.Run(vector.id+"/xOpen", func(t *testing.T) {
				pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
				if pfile == 0 {
					t.Fatal("file allocation")
				}
				defer libc.Xfree(v.tls, pfile)
				pOut := libc.Xmalloc(v.tls, types.Size_t(4))
				defer libc.Xfree(v.tls, pOut)
				*(*int32)(unsafe.Pointer(pOut)) = -1
				before := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls)
				got := storeVFSOpen(v.tls, v.vfs, 0, pfile, sqlite3.SQLITE_OPEN_TEMP_DB|sqlite3.SQLITE_OPEN_READWRITE|sqlite3.SQLITE_OPEN_CREATE|sqlite3.SQLITE_OPEN_DELETEONCLOSE, pOut)
				if got != sqlite3.SQLITE_CANTOPEN || (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods != 0 || *(*int32)(unsafe.Pointer(pOut)) != -1 {
					t.Fatalf("null xOpen got=%d methods=%d out=%d", got, (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods, *(*int32)(unsafe.Pointer(pOut)))
				}
				if after := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls); after != before {
					t.Fatalf("null xOpen path syscalls=%d", after-before)
				}
			})
			continue
		}
		t.Run(vector.id, func(t *testing.T) {
			name, err := libc.CString(vector.path)
			if err != nil {
				t.Fatal(err)
			}
			defer libc.Xfree(v.tls, name)
			for _, mode := range openFlags {
				t.Run("xOpen/"+mode.id, func(t *testing.T) {
					pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
					if pfile == 0 {
						t.Fatal("file allocation")
					}
					defer libc.Xfree(v.tls, pfile)
					pOut := libc.Xmalloc(v.tls, types.Size_t(4))
					defer libc.Xfree(v.tls, pOut)
					*(*int32)(unsafe.Pointer(pOut)) = -1
					before := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls)
					got := storeVFSOpen(v.tls, v.vfs, name, pfile, mode.flags, pOut)
					if got != sqlite3.SQLITE_CANTOPEN || (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods != 0 || *(*int32)(unsafe.Pointer(pOut)) != -1 {
						t.Fatalf("xOpen got=%d methods=%d out=%d", got, (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods, *(*int32)(unsafe.Pointer(pOut)))
					}
					if after := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls); after != before {
						t.Fatalf("xOpen path syscalls=%d", after-before)
					}
				})
			}
			for _, callback := range []struct {
				id  string
				run func() int32
			}{
				{"xAccess", func() int32 {
					res := libc.Xmalloc(v.tls, types.Size_t(4))
					defer libc.Xfree(v.tls, res)
					*(*int32)(unsafe.Pointer(res)) = 1
					got := storeVFSAccess(v.tls, v.vfs, name, sqlite3.SQLITE_ACCESS_EXISTS, res)
					if *(*int32)(unsafe.Pointer(res)) != 0 {
						t.Errorf("xAccess result=%d", *(*int32)(unsafe.Pointer(res)))
					}
					return got
				}},
				{"xDelete", func() int32 { return storeVFSDelete(v.tls, v.vfs, name, 1) }},
				{"xFullPathname", func() int32 {
					out := libc.Xmalloc(v.tls, types.Size_t(128))
					defer libc.Xfree(v.tls, out)
					*(*byte)(unsafe.Pointer(out)) = 0xA5
					got := storeVFSFullPathname(v.tls, v.vfs, name, 128, out)
					if *(*byte)(unsafe.Pointer(out)) != 0xA5 {
						t.Errorf("xFullPathname modified output")
					}
					return got
				}},
			} {
				t.Run(callback.id, func(t *testing.T) {
					before := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls)
					got := callback.run()
					want := int32(sqlite3.SQLITE_IOERR_DELETE)
					if callback.id == "xAccess" {
						want = sqlite3.SQLITE_OK
					} else if callback.id == "xFullPathname" {
						want = sqlite3.SQLITE_CANTOPEN
					}
					if got != want {
						t.Fatalf("%s got=%d want=%d", callback.id, got, want)
					}
					if after := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls); after != before {
						t.Fatalf("%s path syscalls=%d", callback.id, after-before)
					}
				})
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign vector created database: %v", err)
	}
}

func TestStoreNamespaceClosedFlagMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
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
	defer lease.Close()
	for _, leaf := range []string{storeDBName, storeDBName + "-journal"} {
		if err := os.WriteFile(filepath.Join(root, leaf), []byte(leaf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, tc := range []struct {
		name, path string
		flags      int32
		ok         bool
		wantMode   int
	}{
		{"main-readonly", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READONLY, true, unix.O_RDONLY},
		{"main-readwrite", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE, true, unix.O_RDWR},
		{"main-wal-mixture", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_WAL | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"main-journal-mixture", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"main-temp-mixture", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_TEMP_DB | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"main-readonly-create", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READONLY | sqlite3.SQLITE_OPEN_CREATE, false, 0},
		{"main-delete-on-close", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_DELETEONCLOSE | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"main-both-read-modes", v.main, sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READONLY | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"main-no-read-mode", v.main, sqlite3.SQLITE_OPEN_MAIN_DB, false, 0},
		{"journal-readonly", v.main + "-journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_READONLY, true, unix.O_RDONLY},
		{"journal-readwrite", v.main + "-journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_READWRITE, true, unix.O_RDWR},
		{"journal-main-mixture", v.main + "-journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"journal-wal-mixture", v.main + "-journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_WAL | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
		{"journal-temp-mixture", v.main + "-journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_TEMP_JOURNAL | sqlite3.SQLITE_OPEN_READWRITE, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, err := libc.CString(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer libc.Xfree(v.tls, name)
			pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
			if pfile == 0 {
				t.Fatal("file allocation")
			}
			defer libc.Xfree(v.tls, pfile)
			pOut := libc.Xmalloc(v.tls, types.Size_t(4))
			if pOut == 0 {
				t.Fatal("out flags allocation")
			}
			defer libc.Xfree(v.tls, pOut)
			*(*int32)(unsafe.Pointer(pOut)) = -1
			before := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls)
			got := storeVFSOpen(v.tls, v.vfs, name, pfile, tc.flags, pOut)
			if tc.ok {
				if got != sqlite3.SQLITE_OK || *(*int32)(unsafe.Pointer(pOut)) != tc.flags {
					t.Fatalf("accepted flags got=%d out=%#x want=%#x", got, *(*int32)(unsafe.Pointer(pOut)), tc.flags)
				}
				actual, err := unix.FcntlInt(uintptr(storeFile(pfile).fd), unix.F_GETFL, 0)
				if err != nil || actual&unix.O_ACCMODE != tc.wantMode {
					t.Fatalf("descriptor mode=%#x err=%v want=%#x", actual&unix.O_ACCMODE, err, tc.wantMode)
				}
				if got := storeFileClose(v.tls, pfile); got != sqlite3.SQLITE_OK {
					t.Fatalf("close=%d", got)
				}
			} else {
				if got != sqlite3.SQLITE_CANTOPEN || (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods != 0 || *(*int32)(unsafe.Pointer(pOut)) != -1 {
					t.Fatalf("denied flags got=%d methods=%d out=%d", got, (*sqlite3.Tsqlite3_file)(unsafe.Pointer(pfile)).FpMethods, *(*int32)(unsafe.Pointer(pOut)))
				}
				if after := atomic.LoadInt64(&storeContext(v.vfs).pathSyscalls); after != before {
					t.Fatalf("denied flags path syscalls=%d", after-before)
				}
			}
		})
	}
}

func TestStoreNamespaceForeignRetainedConnectionSQL(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	outside := filepath.Join(base, "outside.sqlite")
	if err := os.WriteFile(outside, []byte("outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideBefore, err := nsMetadata(outside)
	if err != nil {
		t.Fatal(err)
	}
	outsideContent, outsideHasContent, err := nsContent(outside, outsideBefore)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = binding.Close()
		_ = lease.Close()
	}()
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE retained(v INTEGER); INSERT INTO retained VALUES (7)"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sql string
	}{
		{"attach-memory", "ATTACH DATABASE ':memory:' AS memory_db"},
		{"attach-other-vfs", "ATTACH DATABASE 'file:" + outside + "?vfs=unix' AS outside_db"},
		{"attach-uri-traversal", "ATTACH DATABASE 'file:" + root + "/../outside.sqlite?vfs=unix' AS traversal_db"},
		{"vacuum-into-outside", "VACUUM INTO '" + outside + "'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := binding.conn.ExecContext(context.Background(), tc.sql); err == nil {
				t.Fatalf("foreign SQL accepted: %s", tc.sql)
			}
		})
	}
	var attached int
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM pragma_database_list WHERE name NOT IN ('main','temp')").Scan(&attached); err != nil {
		t.Fatal(err)
	}
	if attached != 0 {
		t.Fatalf("retained connection escaped with %d attached databases", attached)
	}
	nsAssertUnchanged(t, outside, outsideBefore, outsideContent, outsideHasContent)
	if _, err := os.Stat(filepath.Join(base, "outside.sqlite-journal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign SQL left journal: %v", err)
	}
}

func TestStoreNamespaceHostileLeafMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name  string
		setup func(string) error
	}{
		{"symlink", func(root string) error {
			return os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, storeDBName))
		}},
		{"fifo", func(root string) error { return unix.Mkfifo(filepath.Join(root, storeDBName), 0o600) }},
		{"hardlink", func(root string) error {
			outside := filepath.Join(root, "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
				return err
			}
			return os.Link(outside, filepath.Join(root, storeDBName))
		}},
		{"wrong-mode", func(root string) error {
			return os.WriteFile(filepath.Join(root, storeDBName), []byte("wrong-mode"), 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			if err := tc.setup(root); err != nil {
				t.Fatal(err)
			}
			v, err := newStoreVFS(lease, storeEnroll)
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
				t.Fatal("file allocation")
			}
			defer libc.Xfree(v.tls, pfile)
			if got := storeVFSOpen(v.tls, v.vfs, name, pfile, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
				t.Fatalf("hostile leaf accepted: %d", got)
			}
			if got := storeVFSAccess(v.tls, v.vfs, name, sqlite3.SQLITE_ACCESS_EXISTS, 0); got != sqlite3.SQLITE_IOERR_ACCESS {
				t.Fatalf("hostile access accepted: %d", got)
			}
		})
	}
}

func TestStoreNamespaceReadOnlyNonmutationAndSidecars(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
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
	if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE immutable(v INTEGER); INSERT INTO immutable VALUES (11)"); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, storeDBName)
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeTree := nsTreeSnapshot(t, root)
	reader, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	readBinding, err := openSQLBinding(context.Background(), reader, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	readContext := storeContext(readBinding.vfs.vfs)
	if readContext == nil {
		t.Fatal("readonly binding has no VFS context")
	}
	writeBefore := atomic.LoadInt64(&readContext.writeSyscalls)
	truncateBefore := atomic.LoadInt64(&readContext.truncateSyscalls)
	deleteBefore := atomic.LoadInt64(&readContext.deleteSyscalls)
	syncBefore := atomic.LoadInt64(&readContext.syncSyscalls)
	for _, stmt := range []struct {
		name string
		sql  string
		deny bool
	}{
		{"insert", "INSERT INTO immutable VALUES (12)", true},
		{"update", "UPDATE immutable SET v=13", true},
		{"delete", "DELETE FROM immutable", true},
		{"create", "CREATE TABLE another(v INTEGER)", true},
		{"drop", "DROP TABLE immutable", true},
		{"writable-schema", "PRAGMA writable_schema=ON", false},
		{"journal-mode", "PRAGMA journal_mode=WAL", false},
		{"synchronous", "PRAGMA synchronous=OFF", false},
		{"query-only-off", "PRAGMA query_only=OFF", false},
		{"vacuum", "VACUUM", true},
		{"attach-memory", "ATTACH DATABASE ':memory:' AS foreign_db", true},
	} {
		t.Run(stmt.name, func(t *testing.T) {
			_, err := readBinding.conn.ExecContext(context.Background(), stmt.sql)
			if stmt.deny && err == nil {
				t.Fatalf("readonly SQL mutation accepted: %s", stmt.sql)
			}
		})
	}
	if _, err := readBinding.conn.ExecContext(context.Background(), "INSERT INTO immutable VALUES (14)"); err == nil {
		t.Fatal("readonly SQL guard disabled by pragma sequence")
	}
	if got := atomic.LoadInt64(&readContext.writeSyscalls); got != writeBefore {
		t.Fatalf("readonly SQL issued write syscalls: before=%d after=%d", writeBefore, got)
	}
	if got := atomic.LoadInt64(&readContext.truncateSyscalls); got != truncateBefore {
		t.Fatalf("readonly SQL issued truncate syscalls: before=%d after=%d", truncateBefore, got)
	}
	if got := atomic.LoadInt64(&readContext.deleteSyscalls); got != deleteBefore {
		t.Fatalf("readonly SQL issued delete syscalls: before=%d after=%d", deleteBefore, got)
	}
	if got := atomic.LoadInt64(&readContext.syncSyscalls); got != syncBefore {
		t.Fatalf("readonly SQL issued recovery sync syscalls: before=%d after=%d", syncBefore, got)
	}
	if err := readBinding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	nsAssertTreeUnchanged(t, root, beforeTree)
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || beforeInfo.Size() != afterInfo.Size() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("readonly operation mutated database bytes or metadata")
	}
	for _, sidecar := range []string{storeDBName + "-journal", storeDBName + "-wal", storeDBName + "-shm"} {
		if err := os.WriteFile(filepath.Join(root, sidecar), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		sh, err := openRootLease(context.Background(), root, storeRead)
		if err != nil {
			t.Fatal(err)
		}
		_, got := openSQLBinding(context.Background(), sh, storeRead)
		_ = sh.Close()
		if !errors.Is(got, ErrPending) {
			t.Fatalf("zero-byte %s accepted: %v", sidecar, got)
		}
		if err := os.Remove(filepath.Join(root, sidecar)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreNamespaceReadOnlyDirectCallbackMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
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
	defer lease.Close()
	if err := os.WriteFile(filepath.Join(root, storeDBName), []byte("readonly-direct-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeTree := nsTreeSnapshot(t, root)
	v, err := newStoreVFS(lease, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	name := nsCString(t, v.main, v.tls)
	defer libc.Xfree(v.tls, name)
	pfile := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if pfile == 0 {
		t.Fatal("file allocation")
	}
	defer libc.Xfree(v.tls, pfile)
	if got := storeVFSOpen(v.tls, v.vfs, name, pfile, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READONLY, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("reader xOpen=%d", got)
	}
	defer storeFileClose(v.tls, pfile)
	c := storeContext(v.vfs)
	input := libc.Xmalloc(v.tls, types.Size_t(1))
	if input == 0 {
		t.Fatal("input allocation")
	}
	defer libc.Xfree(v.tls, input)
	*(*byte)(unsafe.Pointer(input)) = 0xFF
	for _, tc := range []struct {
		name string
		run  func() int32
		want int32
	}{
		{"xWrite", func() int32 { return storeFileWrite(v.tls, pfile, input, 1, 0) }, sqlite3.SQLITE_READONLY},
		{"xTruncate", func() int32 { return storeFileTruncate(v.tls, pfile, 0) }, sqlite3.SQLITE_READONLY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := atomic.LoadInt64(&c.writeSyscalls) + atomic.LoadInt64(&c.truncateSyscalls)
			if got := tc.run(); got != tc.want {
				t.Fatalf("%s=%d want=%d", tc.name, got, tc.want)
			}
			after := atomic.LoadInt64(&c.writeSyscalls) + atomic.LoadInt64(&c.truncateSyscalls)
			if after != before {
				t.Fatalf("%s mutating syscalls=%d", tc.name, after-before)
			}
		})
	}
	t.Run("xSync-allowed-reader-callback", func(t *testing.T) {
		syncBefore := atomic.LoadInt64(&c.syncSyscalls)
		callbackBefore := atomic.LoadInt64(&c.callbackCounts[callbackSync])
		if got := storeFileSync(v.tls, pfile, 0); got != sqlite3.SQLITE_OK {
			t.Fatalf("xSync=%d want=%d", got, sqlite3.SQLITE_OK)
		}
		if got := atomic.LoadInt64(&c.callbackCounts[callbackSync]); got != callbackBefore+1 {
			t.Fatalf("xSync callback count=%d want=%d", got, callbackBefore+1)
		}
		if got := atomic.LoadInt64(&c.syncSyscalls); got != syncBefore+1 {
			t.Fatalf("xSync syscall count=%d want=%d", got, syncBefore+1)
		}
		if got := atomic.LoadInt64(&c.writeSyscalls); got != 0 {
			t.Fatalf("reader xSync changed write syscall count=%d", got)
		}
		if got := atomic.LoadInt64(&c.truncateSyscalls); got != 0 {
			t.Fatalf("reader xSync changed truncate syscall count=%d", got)
		}
		if got := atomic.LoadInt64(&c.deleteSyscalls); got != 0 {
			t.Fatalf("reader xSync changed delete syscall count=%d", got)
		}
	})
	t.Run("journal-xOpen", func(t *testing.T) {
		journal := nsCString(t, v.main+"-journal", v.tls)
		defer libc.Xfree(v.tls, journal)
		before := atomic.LoadInt64(&c.pathSyscalls)
		p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
		if p == 0 {
			t.Fatal("journal file allocation")
		}
		defer libc.Xfree(v.tls, p)
		if got := storeVFSOpen(v.tls, v.vfs, journal, p, sqlite3.SQLITE_OPEN_MAIN_JOURNAL|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
			t.Fatalf("journal xOpen=%d", got)
		}
		if atomic.LoadInt64(&c.pathSyscalls) != before || (*sqlite3.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods != 0 {
			t.Fatalf("journal xOpen entered path operations or populated methods")
		}
	})
	t.Run("main-writable-xOpen", func(t *testing.T) {
		before := atomic.LoadInt64(&c.pathSyscalls)
		p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
		if p == 0 {
			t.Fatal("writable file allocation")
		}
		defer libc.Xfree(v.tls, p)
		if got := storeVFSOpen(v.tls, v.vfs, name, p, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE|sqlite3.SQLITE_OPEN_CREATE, 0); got != sqlite3.SQLITE_CANTOPEN {
			t.Fatalf("writable xOpen=%d", got)
		}
		if atomic.LoadInt64(&c.pathSyscalls) != before || (*sqlite3.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods != 0 {
			t.Fatalf("writable xOpen entered path operations or populated methods")
		}
	})
	t.Run("xDelete", func(t *testing.T) {
		journal := nsCString(t, v.main+"-journal", v.tls)
		defer libc.Xfree(v.tls, journal)
		before := atomic.LoadInt64(&c.deleteSyscalls)
		if got := storeVFSDelete(v.tls, v.vfs, journal, 1); got != sqlite3.SQLITE_IOERR_DELETE {
			t.Fatalf("xDelete=%d", got)
		}
		if atomic.LoadInt64(&c.deleteSyscalls) != before {
			t.Fatalf("xDelete entered unlink syscall")
		}
	})
	nsAssertTreeUnchanged(t, root, beforeTree)
}

func TestStoreNamespaceNS001HostileLeafEverySeam(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	classes := []struct {
		id   string
		make func(string, string) error
	}{
		{"symlink", func(root, leaf string) error {
			return os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, leaf))
		}},
		{"fifo", func(root, leaf string) error { return unix.Mkfifo(filepath.Join(root, leaf), 0o600) }},
		{"hardlink", func(root, leaf string) error {
			p := filepath.Join(root, "outside")
			if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
				if err := os.WriteFile(p, []byte("outside-sentinel"), 0o600); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			return os.Link(p, filepath.Join(root, leaf))
		}},
		{"public_mode", func(root, leaf string) error { return os.WriteFile(filepath.Join(root, leaf), []byte("public"), 0o640) }},
		{"wrong_owner", func(root, leaf string) error {
			return os.WriteFile(filepath.Join(root, leaf), []byte("wrong-owner"), 0o600)
		}},
		{"wrong_owner_injected", func(root, leaf string) error {
			return os.WriteFile(filepath.Join(root, leaf), []byte("wrong-owner-injected"), 0o600)
		}},
	}
	ops := []struct {
		id, leaf   string
		applicable bool
		run        func(*testing.T, string, *rootLease, *storeVFS)
	}{
		{"main_root_open", "main", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.openLeaf(storeDBName, os.O_RDONLY, 0); e == nil {
				t.Fatal("accepted hostile main root open")
			}
		}},
		{"main_root_exists", "main", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.hasLeaf(storeDBName); e == nil {
				t.Fatal("accepted hostile main root exists")
			}
		}},
		{"main_vfs_open", "main", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main, v.tls)
			defer libc.Xfree(v.tls, n)
			p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
			defer libc.Xfree(v.tls, p)
			if got := storeVFSOpen(v.tls, v.vfs, n, p, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
				t.Fatalf("xOpen=%d", got)
			}
			if (*sqlite3.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods != 0 {
				t.Fatal("pMethods populated on denial")
			}
		}},
		{"main_vfs_access", "main", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main, v.tls)
			defer libc.Xfree(v.tls, n)
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, 0); got != sqlite3.SQLITE_IOERR_ACCESS {
				t.Fatalf("xAccess=%d", got)
			}
		}},
		{"journal_root_open", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.openLeaf(storeDBName+"-journal", os.O_RDONLY, 0); e == nil {
				t.Fatal("accepted hostile journal root open")
			}
		}},
		{"journal_root_exists", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.hasLeaf(storeDBName + "-journal"); e == nil {
				t.Fatal("accepted hostile journal root exists")
			}
		}},
		{"journal_vfs_open", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main+"-journal", v.tls)
			defer libc.Xfree(v.tls, n)
			p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
			defer libc.Xfree(v.tls, p)
			if got := storeVFSOpen(v.tls, v.vfs, n, p, sqlite3.SQLITE_OPEN_MAIN_JOURNAL|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_CANTOPEN {
				t.Fatalf("journal xOpen=%d", got)
			}
			if (*sqlite3.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods != 0 {
				t.Fatal("journal pMethods populated on denial")
			}
		}},
		{"journal_vfs_access", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main+"-journal", v.tls)
			defer libc.Xfree(v.tls, n)
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, 0); got != sqlite3.SQLITE_IOERR_ACCESS {
				t.Fatalf("journal xAccess=%d", got)
			}
		}},
		{"journal_vfs_delete", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main+"-journal", v.tls)
			defer libc.Xfree(v.tls, n)
			for _, sync := range []int32{0, 1} {
				if got := storeVFSDelete(v.tls, v.vfs, n, sync); got != sqlite3.SQLITE_IOERR_DELETE {
					t.Fatalf("journal xDelete sync=%d got=%d", sync, got)
				}
			}
		}},
		{"journal_root_delete", "journal", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if e := l.deleteJournal(); e == nil {
				t.Fatal("accepted hostile root delete")
			}
		}},
		{"active_marker", "active", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.markerExists(activeMarkerName); e == nil {
				t.Fatal("accepted hostile active marker")
			}
		}},
		{"pending_marker", "pending", true, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if _, e := l.markerExists(pendingMarkerName); e == nil {
				t.Fatal("accepted hostile pending marker")
			}
		}},
	}
	for _, c := range classes {
		for _, op := range ops {
			if !op.applicable {
				continue
			}
			t.Run(op.id+"/"+c.id, func(t *testing.T) {
				if c.id == "wrong_owner" {
					t.Skip("native different-euid fixture unavailable without elevation; this is recorded separately from injected UID cases")
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
				defer lease.Close()
				leaf := storeDBName
				if op.leaf == "journal" {
					leaf += "-journal"
				}
				if op.leaf == "active" {
					leaf = activeMarkerName
				}
				if op.leaf == "pending" {
					leaf = pendingMarkerName
				}
				outside := filepath.Join(root, "outside")
				if err := os.WriteFile(outside, []byte("outside-sentinel"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := c.make(root, leaf); err != nil {
					t.Fatal(err)
				}
				if c.id == "wrong_owner_injected" {
					uid := uint32(unix.Geteuid()) + 1
					if uid == uint32(unix.Geteuid()) {
						t.Fatal("unable to select distinct injected UID")
					}
					lease.uidOverride = uid
				}
				outsideBefore, err := nsMetadata(outside)
				if err != nil {
					t.Fatal(err)
				}
				outsideContent, outsideHasContent, err := nsContent(outside, outsideBefore)
				if err != nil {
					t.Fatal(err)
				}
				hostile := filepath.Join(root, leaf)
				hostileBefore, err := nsMetadata(hostile)
				if err != nil {
					t.Fatal(err)
				}
				hostileContent, hostileHasContent, err := nsContent(hostile, hostileBefore)
				if err != nil {
					t.Fatal(err)
				}
				fdsBefore := nsFDCount()
				v, err := newStoreVFS(lease, storeRecover)
				if err != nil {
					t.Fatal(err)
				}
				defer v.Close()
				op.run(t, root, lease, v)
				if fdsAfter := nsFDCount(); fdsBefore >= 0 && fdsAfter != fdsBefore {
					t.Fatalf("FD leak on %s/%s: before=%d after=%d", op.id, c.id, fdsBefore, fdsAfter)
				}
				nsAssertUnchanged(t, outside, outsideBefore, outsideContent, outsideHasContent)
				nsAssertUnchanged(t, hostile, hostileBefore, hostileContent, hostileHasContent)
			})
		}
	}
}

func nsCString(t *testing.T, s string, tls *libc.TLS) uintptr {
	t.Helper()
	p, e := libc.CString(s)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func nsFDCount() int {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

type nsStatSnapshot struct {
	mode, uid, nlink  uint64
	size              int64
	mtimeSec, mtimeNS int64
	ctimeSec, ctimeNS int64
}

func nsMetadata(path string) (nsStatSnapshot, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nsStatSnapshot{}, err
	}
	mtime := reflect.ValueOf(st).FieldByName("Mtim")
	ctime := reflect.ValueOf(st).FieldByName("Ctim")
	return nsStatSnapshot{
		mode: uint64(st.Mode), uid: uint64(st.Uid), nlink: uint64(st.Nlink), size: st.Size,
		mtimeSec: mtime.FieldByName("Sec").Int(), mtimeNS: mtime.FieldByName("Nsec").Int(),
		ctimeSec: ctime.FieldByName("Sec").Int(), ctimeNS: ctime.FieldByName("Nsec").Int(),
	}, nil
}

func nsContent(path string, st nsStatSnapshot) ([]byte, bool, error) {
	if st.mode&uint64(unix.S_IFMT) != uint64(unix.S_IFREG) {
		return nil, false, nil
	}
	b, err := os.ReadFile(path)
	return b, true, err
}

func nsAssertUnchanged(t *testing.T, path string, before nsStatSnapshot, beforeContent []byte, hadContent bool) {
	t.Helper()
	after, err := nsMetadata(path)
	if err != nil {
		t.Fatalf("metadata %s: %v", path, err)
	}
	if after != before {
		t.Fatalf("metadata changed %s: before=%+v after=%+v", path, before, after)
	}
	if hadContent {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("content %s: %v", path, err)
		}
		if !reflect.DeepEqual(got, beforeContent) {
			t.Fatalf("content changed %s: before=%q after=%q", path, beforeContent, got)
		}
	}
}

type nsEntrySnapshot struct {
	stat    nsStatSnapshot
	content []byte
	hasData bool
}

func nsTreeSnapshot(t *testing.T, root string) map[string]nsEntrySnapshot {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]nsEntrySnapshot, len(entries))
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		stat, err := nsMetadata(path)
		if err != nil {
			t.Fatal(err)
		}
		content, hasData, err := nsContent(path, stat)
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = nsEntrySnapshot{stat: stat, content: content, hasData: hasData}
	}
	return out
}

func nsAssertTreeUnchanged(t *testing.T, root string, before map[string]nsEntrySnapshot) {
	t.Helper()
	after := nsTreeSnapshot(t, root)
	if len(after) != len(before) {
		t.Fatalf("owned entry count changed: before=%d after=%d", len(before), len(after))
	}
	for name, old := range before {
		got, ok := after[name]
		if !ok {
			t.Fatalf("owned entry removed: %s", name)
		}
		if got.stat != old.stat || got.hasData != old.hasData || !reflect.DeepEqual(got.content, old.content) {
			t.Fatalf("owned entry changed: %s before=%+v after=%+v", name, old, got)
		}
	}
}

func TestStoreNamespaceNS001PostSuccessSubstitution(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name string
		leaf string
		run  func(*testing.T, string, *rootLease, *storeVFS)
	}{
		{"main-root-exists", storeDBName, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if ok, e := l.hasLeaf(storeDBName); e != nil || !ok {
				t.Fatalf("initial exists=%v %v", ok, e)
			}
			if e := nsReplaceLeaf(root, storeDBName); e == nil {
				if ok, _ := l.hasLeaf(storeDBName); ok {
					t.Fatal("replacement accepted")
				}
			}
		}},
		{"main-vfs-access", storeDBName, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main, v.tls)
			defer libc.Xfree(v.tls, n)
			r := libc.Xmalloc(v.tls, 4)
			defer libc.Xfree(v.tls, r)
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, r); got != sqlite3.SQLITE_OK || *(*int32)(unsafe.Pointer(r)) != 1 {
				t.Fatalf("initial access=%d/%d", got, *(*int32)(unsafe.Pointer(r)))
			}
			if e := nsReplaceLeaf(root, storeDBName); e != nil {
				t.Fatal(e)
			}
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, r); got != sqlite3.SQLITE_IOERR_ACCESS {
				t.Fatalf("replacement access=%d", got)
			}
		}},
		{"journal-root-exists", storeDBName + "-journal", func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if ok, e := l.hasLeaf(storeDBName + "-journal"); e != nil || !ok {
				t.Fatalf("initial exists=%v %v", ok, e)
			}
			if e := nsReplaceLeaf(root, storeDBName+"-journal"); e == nil {
				if ok, _ := l.hasLeaf(storeDBName + "-journal"); ok {
					t.Fatal("replacement accepted")
				}
			}
		}},
		{"journal-vfs-access", storeDBName + "-journal", func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			n := nsCString(t, v.main+"-journal", v.tls)
			defer libc.Xfree(v.tls, n)
			r := libc.Xmalloc(v.tls, 4)
			defer libc.Xfree(v.tls, r)
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, r); got != sqlite3.SQLITE_OK || *(*int32)(unsafe.Pointer(r)) != 1 {
				t.Fatalf("initial access=%d/%d", got, *(*int32)(unsafe.Pointer(r)))
			}
			if e := nsReplaceLeaf(root, storeDBName+"-journal"); e != nil {
				t.Fatal(e)
			}
			if got := storeVFSAccess(v.tls, v.vfs, n, sqlite3.SQLITE_ACCESS_EXISTS, r); got != sqlite3.SQLITE_IOERR_ACCESS {
				t.Fatalf("replacement access=%d", got)
			}
		}},
		{"active-marker", activeMarkerName, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if ok, e := l.markerExists(activeMarkerName); e != nil || !ok {
				t.Fatalf("initial marker=%v %v", ok, e)
			}
			if e := nsReplaceLeaf(root, activeMarkerName); e == nil {
				if ok, _ := l.markerExists(activeMarkerName); ok {
					t.Fatal("replacement accepted")
				}
			}
		}},
		{"pending-marker", pendingMarkerName, func(t *testing.T, root string, l *rootLease, v *storeVFS) {
			if ok, e := l.markerExists(pendingMarkerName); e != nil || !ok {
				t.Fatalf("initial marker=%v %v", ok, e)
			}
			if e := nsReplaceLeaf(root, pendingMarkerName); e == nil {
				if ok, _ := l.markerExists(pendingMarkerName); ok {
					t.Fatal("replacement accepted")
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := filepath.EvalSymlinks(t.TempDir())
			root := filepath.Join(base, "store")
			l, e := openRootLease(context.Background(), root, storeEnroll)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			if e := os.WriteFile(filepath.Join(root, tc.leaf), []byte("owned"), 0o600); e != nil {
				t.Fatal(e)
			}
			outside := filepath.Join(root, "outside")
			if e := os.WriteFile(outside, []byte("outside-sentinel"), 0o600); e != nil {
				t.Fatal(e)
			}
			outsideBefore, e := nsMetadata(outside)
			if e != nil {
				t.Fatal(e)
			}
			outsideContent, outsideHasContent, e := nsContent(outside, outsideBefore)
			if e != nil {
				t.Fatal(e)
			}
			fdsBefore := nsFDCount()
			v, e := newStoreVFS(l, storeRecover)
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			tc.run(t, root, l, v)
			if fdsAfter := nsFDCount(); fdsBefore >= 0 && fdsAfter != fdsBefore {
				t.Fatalf("FD leak on post-success seam %s: before=%d after=%d", tc.name, fdsBefore, fdsAfter)
			}
			nsAssertUnchanged(t, outside, outsideBefore, outsideContent, outsideHasContent)
			saved := filepath.Join(root, tc.leaf+".saved")
			savedBefore, e := nsMetadata(saved)
			if e != nil {
				t.Fatal(e)
			}
			savedContent, savedHasContent, e := nsContent(saved, savedBefore)
			if e != nil {
				t.Fatal(e)
			}
			nsAssertUnchanged(t, saved, savedBefore, savedContent, savedHasContent)
		})
	}
}

func nsReplaceLeaf(root, leaf string) error {
	old := filepath.Join(root, leaf)
	if err := os.Rename(old, old+".saved"); err != nil {
		return err
	}
	return os.Symlink(filepath.Join(root, "outside"), old)
}

func TestStoreNamespaceNS001PostSuccessOpenSubstitution(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name, leaf, virtual string
		flags               int32
	}{
		{"main-vfs-open", storeDBName, "main", sqlite3.SQLITE_OPEN_MAIN_DB | sqlite3.SQLITE_OPEN_READWRITE},
		{"journal-vfs-open", storeDBName + "-journal", "journal", sqlite3.SQLITE_OPEN_MAIN_JOURNAL | sqlite3.SQLITE_OPEN_READWRITE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := filepath.EvalSymlinks(t.TempDir())
			root := filepath.Join(base, "store")
			l, e := openRootLease(context.Background(), root, storeEnroll)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			if e := os.WriteFile(filepath.Join(root, tc.leaf), []byte("owned"), 0o600); e != nil {
				t.Fatal(e)
			}
			outside := filepath.Join(root, "outside")
			if e := os.WriteFile(outside, []byte("outside-sentinel"), 0o600); e != nil {
				t.Fatal(e)
			}
			outsideBefore, e := nsMetadata(outside)
			if e != nil {
				t.Fatal(e)
			}
			outsideContent, outsideHasContent, e := nsContent(outside, outsideBefore)
			if e != nil {
				t.Fatal(e)
			}
			v, e := newStoreVFS(l, storeRecover)
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			name := v.main
			if tc.virtual == "journal" {
				name += "-journal"
			}
			n := nsCString(t, name, v.tls)
			defer libc.Xfree(v.tls, n)
			p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
			defer libc.Xfree(v.tls, p)
			if got := storeVFSOpen(v.tls, v.vfs, n, p, tc.flags, 0); got != sqlite3.SQLITE_OK {
				t.Fatalf("initial open=%d", got)
			}
			if got := storeFileClose(v.tls, p); got != sqlite3.SQLITE_OK {
				t.Fatalf("close=%d", got)
			}
			fdsBefore := nsFDCount()
			if e := nsReplaceLeaf(root, tc.leaf); e != nil {
				t.Fatal(e)
			}
			if got := storeVFSOpen(v.tls, v.vfs, n, p, tc.flags, 0); got != sqlite3.SQLITE_CANTOPEN {
				t.Fatalf("replacement open=%d", got)
			}
			if (*sqlite3.Tsqlite3_file)(unsafe.Pointer(p)).FpMethods != 0 {
				t.Fatal("replacement pMethods populated")
			}
			if fdsAfter := nsFDCount(); fdsBefore >= 0 && fdsAfter != fdsBefore {
				t.Fatalf("FD leak on post-success open %s: before=%d after=%d", tc.name, fdsBefore, fdsAfter)
			}
			nsAssertUnchanged(t, outside, outsideBefore, outsideContent, outsideHasContent)
		})
	}
}
