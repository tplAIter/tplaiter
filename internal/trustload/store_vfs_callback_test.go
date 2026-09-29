//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"unsafe"

	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreBindingSetupFaultMatrix(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	phases := []string{"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL", "query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema", "query:PRAGMA query_only", "query:PRAGMA journal_mode", "query:PRAGMA synchronous"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			ctx := context.WithValue(context.Background(), storeSetupFaultKey{}, storeSetupFault{phase: phase, err: errors.New("injected setup failure")})
			if b, err := openSQLBinding(ctx, lease, storeEnroll); err == nil || b != nil {
				t.Fatalf("%s returned usable binding", phase)
			}
			if !lease.valid() {
				t.Fatalf("%s invalidated lease", phase)
			}
		})
	}
	for _, phase := range append(phases[:3], append(phases[5:9], "exec:PRAGMA query_only=ON")...) {
		t.Run("reader/"+phase, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "store")
			seed, err := openRootLease(context.Background(), root, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			b, err := openSQLBinding(context.Background(), seed, storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.conn.ExecContext(context.Background(), "CREATE TABLE t(v)"); err != nil {
				t.Fatal(err)
			}
			_ = b.Close()
			_ = seed.Close()
			lease, err := openRootLease(context.Background(), root, storeRead)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			ctx := context.WithValue(context.Background(), storeSetupFaultKey{}, storeSetupFault{phase: phase, err: errors.New("injected setup failure")})
			if b, err := openSQLBinding(ctx, lease, storeRead); err == nil || b != nil {
				t.Fatalf("%s returned usable reader", phase)
			}
			if !lease.valid() {
				t.Fatalf("%s invalidated reader lease", phase)
			}
		})
	}
}

// TestStoreVFSGeneratedCallbackDispatch invokes the registered ABI slots, not
// the Go callback names.  Its function types match the generated SQLite VFS
// dispatcher at cached lib/sqlite.go:27952 and :34636.
func TestStoreVFSGeneratedCallbackDispatch(t *testing.T) {
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
	tls := v.tls
	name, err := libc.CString(v.main)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, name)
	out := libc.Xmalloc(tls, 4096)
	if out == 0 {
		t.Fatal("malloc")
	}
	defer libc.Xfree(tls, out)
	vfs := (*sqlite3.Tsqlite3_vfs)(libcPtr(v.vfs))
	full := *(*func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxFullPathname}))
	if got := full(tls, v.vfs, name, 4096, out); got != sqlite3.SQLITE_OK || libc.GoString(out) != v.main {
		t.Fatalf("full=%d path=%q", got, libc.GoString(out))
	}
	file := libc.Xmalloc(tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if file == 0 {
		t.Fatal("malloc")
	}
	defer libc.Xfree(tls, file)
	open := *(*func(*libc.TLS, uintptr, sqlite3.Tsqlite3_filename, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxOpen}))
	if got := open(tls, v.vfs, name, file, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE|sqlite3.SQLITE_OPEN_CREATE, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("open=%d", got)
	}
	defer storeFileClose(tls, file)
	// Exercise unsupported VFS slots through their registered ABI pointers.
	dlOpen := *(*func(*libc.TLS, uintptr, uintptr) uintptr)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxDlOpen}))
	if dlOpen(tls, v.vfs, name) != 0 {
		t.Fatal("dlopen accepted")
	}
	dlSym := *(*func(*libc.TLS, uintptr, uintptr, uintptr) uintptr)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxDlSym}))
	if dlSym(tls, v.vfs, 0, name) != 0 {
		t.Fatal("dlsym accepted")
	}
	dlErr := *(*func(*libc.TLS, uintptr, int32, uintptr))(unsafe.Pointer(&struct{ p uintptr }{vfs.FxDlError}))
	dlErr(tls, v.vfs, 1, out)
	if *(*byte)(libcPtr(out)) != 0 {
		t.Fatal("dlerror not nul")
	}
	random := *(*func(*libc.TLS, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxRandomness}))
	if random(tls, v.vfs, 1, out) != 0 {
		t.Fatal("randomness")
	}
	sleep := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxSleep}))
	if sleep(tls, v.vfs, 7) != 7 {
		t.Fatal("sleep result")
	}
	methods := (*sqlite3.Tsqlite3_io_methods)(libcPtr((*sqlite3.Tsqlite3_file)(libcPtr(file)).FpMethods))
	size := *(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxFileSize}))
	if size(tls, file, out) != sqlite3.SQLITE_OK {
		t.Fatal("filesize")
	}
	control := *(*func(*libc.TLS, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxFileControl}))
	if control(tls, file, sqlite3.SQLITE_FCNTL_LOCKSTATE, out) != sqlite3.SQLITE_OK {
		t.Fatal("control")
	}
}

func TestStoreVFSGeneratedCallbackRemainingSlots(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	v, err := newStoreVFS(lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	tls := v.tls
	name, err := libc.CString(v.main)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, name)
	journal, err := libc.CString(v.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, journal)
	foreign, err := libc.CString("foreign.db")
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(tls, foreign)
	out := libc.Xmalloc(tls, 4096)
	if out == 0 {
		t.Fatal("malloc output")
	}
	defer libc.Xfree(tls, out)
	file := libc.Xmalloc(tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if file == 0 {
		t.Fatal("malloc file")
	}
	defer libc.Xfree(tls, file)
	vfs := (*sqlite3.Tsqlite3_vfs)(libcPtr(v.vfs))
	open := *(*func(*libc.TLS, uintptr, sqlite3.Tsqlite3_filename, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxOpen}))
	if got := open(tls, v.vfs, name, file, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE|sqlite3.SQLITE_OPEN_CREATE, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("open=%d", got)
	}
	methods := (*sqlite3.Tsqlite3_io_methods)(libcPtr((*sqlite3.Tsqlite3_file)(libcPtr(file)).FpMethods))
	close := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxClose}))
	read := *(*func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Tsqlite3_int64) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxRead}))
	write := *(*func(*libc.TLS, uintptr, uintptr, int32, sqlite3.Tsqlite3_int64) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxWrite}))
	truncate := *(*func(*libc.TLS, uintptr, sqlite3.Tsqlite3_int64) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxTruncate}))
	sync := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxSync}))
	lock := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxLock}))
	unlock := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxUnlock}))
	reserved := *(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxCheckReservedLock}))
	sector := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxSectorSize}))
	device := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{methods.FxDeviceCharacteristics}))
	delete := *(*func(*libc.TLS, uintptr, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxDelete}))
	access := *(*func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxAccess}))
	dlClose := *(*func(*libc.TLS, uintptr, uintptr))(unsafe.Pointer(&struct{ p uintptr }{vfs.FxDlClose}))
	currentTime := *(*func(*libc.TLS, uintptr, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxCurrentTime}))
	lastError := *(*func(*libc.TLS, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{vfs.FxGetLastError}))

	if got := access(tls, v.vfs, name, sqlite3.SQLITE_ACCESS_EXISTS, out); got != sqlite3.SQLITE_OK || *(*int32)(libcPtr(out)) != 1 {
		t.Fatalf("access main got=%d result=%d", got, *(*int32)(libcPtr(out)))
	}
	if got := access(tls, v.vfs, foreign, sqlite3.SQLITE_ACCESS_EXISTS, out); got != sqlite3.SQLITE_OK || *(*int32)(libcPtr(out)) != 0 {
		t.Fatalf("access foreign got=%d result=%d", got, *(*int32)(libcPtr(out)))
	}
	if got := delete(tls, v.vfs, journal, 1); got != sqlite3.SQLITE_OK {
		t.Fatalf("delete journal=%d", got)
	}
	dlClose(tls, v.vfs, 0)
	if got := currentTime(tls, v.vfs, out); got != sqlite3.SQLITE_ERROR {
		t.Fatalf("current time=%d", got)
	}
	if got := lastError(tls, v.vfs, 0, out); got != 0 {
		t.Fatalf("last error=%d", got)
	}
	if got := sector(tls, file); got != 4096 {
		t.Fatalf("sector=%d", got)
	}
	if got := device(tls, file); got != 0 {
		t.Fatalf("device=%d", got)
	}
	if got := lock(tls, file, sqlite3.SQLITE_LOCK_SHARED); got != sqlite3.SQLITE_OK {
		t.Fatalf("shared lock=%d", got)
	}
	if got := lock(tls, file, sqlite3.SQLITE_LOCK_RESERVED); got != sqlite3.SQLITE_OK {
		t.Fatalf("reserved lock=%d", got)
	}
	if got := reserved(tls, file, out); got != sqlite3.SQLITE_OK || *(*int32)(libcPtr(out)) != 1 {
		t.Fatalf("reserved check got=%d result=%d", got, *(*int32)(libcPtr(out)))
	}
	if got := unlock(tls, file, sqlite3.SQLITE_LOCK_NONE); got != sqlite3.SQLITE_OK {
		t.Fatalf("unlock=%d", got)
	}
	if got := reserved(tls, file, out); got != sqlite3.SQLITE_OK || *(*int32)(libcPtr(out)) != 0 {
		t.Fatalf("reserved after unlock got=%d result=%d", got, *(*int32)(libcPtr(out)))
	}
	if got := write(tls, file, name, 0, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("zero write=%d", got)
	}
	if got := truncate(tls, file, 0); got != sqlite3.SQLITE_OK {
		t.Fatalf("truncate=%d", got)
	}
	if got := sync(tls, file, sqlite3.SQLITE_SYNC_NORMAL); got != sqlite3.SQLITE_OK {
		t.Fatalf("sync=%d", got)
	}
	if got := read(tls, file, out, 4, 0); got != sqlite3.SQLITE_IOERR_SHORT_READ {
		t.Fatalf("empty read=%d", got)
	}
	for i := 0; i < 4; i++ {
		if *(*byte)(libcPtr(out + uintptr(i))) != 0 {
			t.Fatalf("short read byte %d not zero", i)
		}
	}
	if got := close(tls, file); got != sqlite3.SQLITE_OK {
		t.Fatalf("close=%d", got)
	}
}

func TestStoreVFSObservedSQLiteTransactionCallbacks(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	proof := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
	binding, err := openSQLBinding(ctx, lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, "CREATE TABLE proof(v INTEGER); INSERT INTO proof VALUES (7)"); err != nil {
		t.Fatal(err)
	}
	c := (*vfsContext)(libcPtr(binding.vfs.ctx))
	for _, tc := range []struct {
		name string
		kind int
	}{
		{"open", callbackOpen}, {"read", callbackRead}, {"write", callbackWrite}, {"sync", callbackSync},
		{"delete", callbackDelete}, {"lock", callbackLock}, {"unlock", callbackUnlock}, {"filesize", callbackFileSize}, {"control", callbackFileControl}, {"close", callbackClose},
	} {
		if got := atomic.LoadInt64(&c.callbackCounts[tc.kind]); got == 0 {
			t.Errorf("transaction did not invoke %s callback", tc.name)
		}
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	proof.mu.Lock()
	allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
	proof.mu.Unlock()
	if allocs != 4 || frees != 4 || registers != 1 || unregisters != 1 {
		t.Fatalf("observer lifecycle allocs=%d frees=%d registers=%d unregisters=%d", allocs, frees, registers, unregisters)
	}
}

func TestStoreBindingSetupCancellationAndCleanup(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	phases := []string{"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL", "query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema", "query:PRAGMA query_only", "query:PRAGMA journal_mode", "query:PRAGMA synchronous"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			proof := &storeProofObserver{}
			ctx, cancel := context.WithCancel(context.Background())
			ctx = context.WithValue(ctx, storeProofObserverKey{}, proof)
			ctx = context.WithValue(ctx, storeSetupFaultKey{}, storeSetupFault{phase: phase, cancel: cancel})
			if b, err := openSQLBinding(ctx, lease, storeEnroll); err == nil || b != nil {
				t.Fatalf("cancelled phase %s returned binding", phase)
			}
			proof.mu.Lock()
			allocs, frees, registers, unregisters := proof.allocs, proof.frees, proof.registers, proof.unregisters
			proof.mu.Unlock()
			if allocs != frees || registers != unregisters || allocs == 0 {
				t.Fatalf("phase %s cleanup allocs=%d frees=%d registers=%d unregisters=%d", phase, allocs, frees, registers, unregisters)
			}
			if !lease.valid() {
				t.Fatal("lease invalidated")
			}
		})
	}
}

func TestStoreBindingFixedConnectionPolicy(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := openRootLease(context.Background(), filepath.Join(base, "store"), storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := openSQLBinding(context.Background(), lease, 0); err == nil {
		t.Fatal("zero mode accepted")
	}
	b, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, q := range []string{"PRAGMA temp_store", "PRAGMA trusted_schema", "PRAGMA journal_mode", "PRAGMA synchronous"} {
		var x any
		if err := b.conn.QueryRowContext(context.Background(), q).Scan(&x); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := b.gate.Connect(context.Background()); err == nil {
		t.Fatal("connector replaced retained connection")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.gate.Connect(context.Background()); err == nil {
		t.Fatal("closed connector accepted reconnect")
	}
}

func TestStoreBindingLeaseModesAndCancellation(t *testing.T) {
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
	if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE mode_proof(v INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := seedBinding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	read, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openRootLease(context.Background(), root, storeRefresh); err == nil {
		t.Fatal("SH lease permitted writer")
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	write, err := openRootLease(context.Background(), root, storeRefresh)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	if b, err := openSQLBinding(context.Background(), write, storeRead); err != nil {
		t.Fatalf("EX internal readonly binding: %v", err)
	} else if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	cancel, stop := context.WithCancel(context.Background())
	stop()
	if _, err := openSQLBinding(cancel, write, storeRefresh); err == nil {
		t.Fatal("cancelled binding accepted")
	}
}
