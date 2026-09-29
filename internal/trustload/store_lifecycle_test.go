//go:build darwin || linux

package trustload

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreLifecycleLIFE03SuccessfulWorkloadGCAndTwoSessions(t *testing.T) {
	ctx := context.Background()
	leaseA, rootA := newLifecycleLeaseMode(t, storeEnroll)
	leaseB, rootB := newLifecycleLeaseMode(t, storeEnroll)
	if rootA == rootB {
		t.Fatal("independent sessions reused root")
	}
	observerA := &storeProofObserver{}
	observerB := &storeProofObserver{}
	bindingA, err := openSQLBinding(context.WithValue(ctx, storeProofObserverKey{}, observerA), leaseA, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	bindingB, err := openSQLBinding(context.WithValue(ctx, storeProofObserverKey{}, observerB), leaseB, storeEnroll)
	if err != nil {
		_ = bindingA.Close()
		_ = leaseA.Close()
		t.Fatal(err)
	}
	if bindingA.vfs == bindingB.vfs || bindingA.vfs.ctx == bindingB.vfs.ctx {
		t.Fatal("independent sessions share VFS state")
	}
	if _, err := bindingA.conn.ExecContext(ctx, "CREATE TABLE lifecycle_state(id INTEGER PRIMARY KEY, payload BLOB)"); err != nil {
		t.Fatal(err)
	}
	if _, err := bindingB.conn.ExecContext(ctx, "CREATE TABLE lifecycle_state(id INTEGER PRIMARY KEY, payload BLOB)"); err != nil {
		t.Fatal(err)
	}

	gcStarted := make(chan struct{})
	gcProgress := make(chan uint64, 1)
	gcStop := make(chan struct{})
	var gcStopOnce sync.Once
	var gcCompleted atomic.Uint64
	var gcWG sync.WaitGroup
	gcWG.Add(1)
	go func() {
		defer gcWG.Done()
		close(gcStarted)
		for {
			runtime.GC()
			completed := gcCompleted.Add(1)
			select {
			case gcProgress <- completed:
			default:
			}
			runtime.Gosched()
			select {
			case <-gcStop:
				return
			default:
			}
		}
	}()
	<-gcStarted
	stopGC := func() {
		gcStopOnce.Do(func() { close(gcStop) })
		gcWG.Wait()
	}
	t.Cleanup(stopGC)

	tx, err := bindingA.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	gcBaseline := gcCompleted.Load()
	callbackBefore := atomic.LoadInt64(&(*vfsContext)(libcPtr(bindingA.vfs.ctx)).callbackCounts[callbackRead]) + atomic.LoadInt64(&(*vfsContext)(libcPtr(bindingA.vfs.ctx)).callbackCounts[callbackWrite])
	if _, err := tx.ExecContext(ctx, "INSERT INTO lifecycle_state(id,payload) VALUES(?,?)", 1, []byte("committed-A")); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	callbackDuringTransaction := atomic.LoadInt64(&(*vfsContext)(libcPtr(bindingA.vfs.ctx)).callbackCounts[callbackRead]) + atomic.LoadInt64(&(*vfsContext)(libcPtr(bindingA.vfs.ctx)).callbackCounts[callbackWrite])
	if callbackDuringTransaction <= callbackBefore {
		_ = tx.Rollback()
		t.Fatalf("transaction did not advance VFS callbacks: before=%d after=%d", callbackBefore, callbackDuringTransaction)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	gcObserved := false
	for !gcObserved {
		select {
		case completed := <-gcProgress:
			if completed > gcBaseline {
				gcObserved = true
			}
		case <-deadline.C:
			_ = tx.Rollback()
			t.Fatalf("no completed GC cycle while transaction remained open: baseline=%d completed=%d", gcBaseline, gcCompleted.Load())
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rollback, err := bindingA.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rollback.ExecContext(ctx, "INSERT INTO lifecycle_state(id,payload) VALUES(?,?)", 2, []byte("rolled-back-A")); err != nil {
		_ = rollback.Rollback()
		t.Fatal(err)
	}
	if err := rollback.Rollback(); err != nil {
		t.Fatal(err)
	}
	stopGC()
	assertLifecycleState(t, bindingA, "committed-A", "3f44c243c43bac57bbad4930b28a76d10dfffdd08a1afe72a271638a05a520e9", "8dd651b703201a04ee31067df32dc0f2413a9ecd13cb45bf2a036f2c1388160b")

	if err := bindingA.Close(); err != nil {
		t.Fatal(err)
	}
	if err := leaseA.Close(); err != nil {
		t.Fatal(err)
	}
	reopenLeaseA, err := openRootLease(ctx, rootA, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	reopenObserverA := &storeProofObserver{}
	reopenA, err := openSQLBinding(context.WithValue(ctx, storeProofObserverKey{}, reopenObserverA), reopenLeaseA, storeRead)
	if err != nil {
		_ = reopenLeaseA.Close()
		t.Fatal(err)
	}
	assertLifecycleState(t, reopenA, "committed-A", "3f44c243c43bac57bbad4930b28a76d10dfffdd08a1afe72a271638a05a520e9", "8dd651b703201a04ee31067df32dc0f2413a9ecd13cb45bf2a036f2c1388160b")
	if err := reopenA.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reopenLeaseA.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := bindingB.conn.ExecContext(ctx, "INSERT INTO lifecycle_state(id,payload) VALUES(?,?)", 1, []byte("committed-B")); err != nil {
		t.Fatalf("session B write after A close: %v", err)
	}
	assertLifecycleState(t, bindingB, "committed-B", "3138f61790c6e18af6ad173c87f7b13562fc3f2c7330f0fd7deb94872e98d3e5", "3391ba4747bfacde202ea0b8be5d4e6ac088383e60db0a997a5e868ddfbb8fb3")
	if err := bindingB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := leaseB.Close(); err != nil {
		t.Fatal(err)
	}
	assertLifecycleBalanced(t, observerA)
	assertLifecycleBalanced(t, observerB)
	assertLifecycleBalanced(t, reopenObserverA)
}

func assertLifecycleState(t *testing.T, binding *sqlBinding, wantPayload, wantBlobHash, wantStateHash string) {
	t.Helper()
	var id int
	var payload []byte
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT id,payload FROM lifecycle_state ORDER BY id LIMIT 1").Scan(&id, &payload); err != nil {
		t.Fatal(err)
	}
	if id != 1 || string(payload) != wantPayload {
		t.Fatalf("state id=%d payload=%q want id=1 payload=%q", id, payload, wantPayload)
	}
	blobDigest := sha256.Sum256(payload)
	if got := hex.EncodeToString(blobDigest[:]); got != wantBlobHash {
		t.Fatalf("blob hash=%s want=%s", got, wantBlobHash)
	}
	stateDigest := sha256.Sum256([]byte(strconv.Itoa(id) + ":" + string(payload)))
	if got := hex.EncodeToString(stateDigest[:]); got != wantStateHash {
		t.Fatalf("state hash=%s want=%s", got, wantStateHash)
	}
	stmt, err := binding.conn.PrepareContext(context.Background(), "SELECT id,payload FROM lifecycle_state ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := stmt.QueryContext(context.Background())
	if err != nil {
		_ = stmt.Close()
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var gotID int
		var gotPayload []byte
		if err := rows.Scan(&gotID, &gotPayload); err != nil {
			t.Fatal(err)
		}
		count++
		if gotID != id || string(gotPayload) != wantPayload {
			t.Fatalf("row %d id=%d payload=%q", count, gotID, gotPayload)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows=%d want=1", count)
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreLifecycleLIFE04TerminalRetentionAndTeardown(t *testing.T) {
	t.Run("extra-live-file-retains-owner", testLifecycleExtraLiveFile)
	t.Run("post-native-close-error-retains-owner", testLifecyclePostNativeCloseError)
	t.Run("physical-close-error-retains-owner", testLifecyclePhysicalCloseError)
	t.Run("vfs-unregister-error-retains-owner", testLifecycleVFSUnregisterError)
}

func testLifecycleExtraLiveFile(t *testing.T) {
	lease, binding, observer := newTerminalBinding(t)
	file, name := lifecycleOpenExtraFile(t, binding)
	rootFD := lease.fd
	session := &storeSession{lease: lease, binding: binding}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("session close with live file=%v", err)
	}
	first := assertTerminalRetained(t, lease, binding, observer, name)
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("repeat session close with live file=%v", err)
	}
	if got := captureTerminalSnapshot(t, lease, binding, observer, name); got != first {
		t.Fatalf("repeat session close changed retained snapshot: first=%+v second=%+v", first, got)
	}
	if binding.closed {
		t.Fatal("binding marked closed with live file")
	}
	if binding.closeErr == nil || atomic.LoadInt64(&(*vfsContext)(libcPtr(binding.vfs.ctx)).openFiles) != 1 {
		t.Fatal("terminal live-file state was not retained")
	}
	if !lifecycleVFSFound(t, binding.vfs, name) {
		t.Fatal("VFS unregistered while an extra file remained live")
	}
	if err := binding.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("repeat terminal close=%v", err)
	}
	if got := storeFileClose(binding.vfs.tls, file); got != sqlite3.SQLITE_OK {
		t.Fatalf("extra xClose=%d", got)
	}
	if got := storeFileClose(binding.vfs.tls, file); got == sqlite3.SQLITE_OK || atomic.LoadInt64(&(*vfsContext)(libcPtr(binding.vfs.ctx)).openFiles) != 0 {
		t.Fatal("repeat xClose changed terminal file state")
	}
	libc.Xfree(binding.vfs.tls, file)
	if err := binding.vfs.Close(); err != nil {
		t.Fatal(err)
	}
	if lifecycleVFSFound(t, binding.vfs, name) {
		t.Fatal("VFS remained registered after isolated cleanup")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedFDBad(t, rootFD)
	assertLifecycleBalanced(t, observer)
}

func testLifecyclePostNativeCloseError(t *testing.T) {
	lease, binding, observer := newTerminalBinding(t)
	c := (*vfsContext)(libcPtr(binding.vfs.ctx))
	atomic.StoreInt64(&c.fault, storeFaultClose)
	rootFD := lease.fd
	session := &storeSession{lease: lease, binding: binding}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("post-native close error=%v", err)
	}
	first := assertTerminalRetained(t, lease, binding, observer, binding.vfs.name)
	if !first.vfsFound || !first.registryPresent {
		t.Fatal("post-native close released VFS registry before cleanup")
	}
	if binding.closed || binding.closeErr == nil || atomic.LoadInt64(&c.closeErrors) != 1 {
		t.Fatal("post-native close terminal state not retained")
	}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("repeat post-native session close=%v", err)
	}
	if got := captureTerminalSnapshot(t, lease, binding, observer, binding.vfs.name); got != first {
		t.Fatalf("repeat post-native close changed retained snapshot: first=%+v second=%+v", first, got)
	}
	atomic.StoreInt64(&c.fault, storeFaultNone)
	atomic.StoreInt64(&c.closeErrors, 0)
	if err := binding.vfs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedFDBad(t, rootFD)
	assertLifecycleBalanced(t, observer)
}

func testLifecyclePhysicalCloseError(t *testing.T) {
	lease, binding, observer := newTerminalBinding(t)
	original := storePhysicalClose
	t.Cleanup(func() { storePhysicalClose = original })
	var closeCalls atomic.Int64
	storePhysicalClose = func(conn *sql.Conn) error {
		closeCalls.Add(1)
		if err := conn.Close(); err != nil {
			return err
		}
		return errors.New("injected physical close error")
	}
	rootFD := lease.fd
	session := &storeSession{lease: lease, binding: binding}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("physical close error=%v", err)
	}
	first := captureTerminalSnapshotDetached(t, lease, binding.vfs.name, observer)
	if first.vfsFound || first.registryPresent {
		t.Fatal("physical close error retained VFS registry after native connection close")
	}
	if !first.leaseValid || !first.rootFDLive {
		t.Fatalf("physical close error did not retain owner lease/root FD: %+v", first)
	}
	if binding.closed || binding.closeErr == nil {
		t.Fatal("physical close terminal state not retained")
	}
	if closeCalls.Load() != 1 {
		t.Fatalf("physical close calls=%d want=1", closeCalls.Load())
	}
	fresh, err := openRootLease(context.Background(), lease.path, storeRefresh)
	if fresh != nil || !errors.Is(err, ErrRefreshConflict) {
		t.Fatalf("fresh EX while physical-close owner retained lease=%v err=%v", fresh, err)
	}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("repeat physical session close=%v", err)
	}
	second := captureTerminalSnapshotDetached(t, lease, binding.vfs.name, observer)
	if second != first {
		t.Fatalf("repeat physical close changed retained snapshot: first=%+v second=%+v", first, second)
	}
	if closeCalls.Load() != 1 {
		t.Fatalf("repeat physical close calls=%d want=1", closeCalls.Load())
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedFDBad(t, rootFD)
	assertLifecycleBalanced(t, observer)
}

func testLifecycleVFSUnregisterError(t *testing.T) {
	lease, binding, observer := newTerminalBinding(t)
	original := storeVFSUnregister
	t.Cleanup(func() { storeVFSUnregister = original })
	storeVFSUnregister = func(*libc.TLS, uintptr) int32 { return sqlite3.SQLITE_BUSY }
	rootFD := lease.fd
	name := binding.vfs.name
	session := &storeSession{lease: lease, binding: binding}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("VFS unregister error=%v", err)
	}
	first := assertTerminalRetained(t, lease, binding, observer, name)
	if binding.closed || binding.closeErr == nil {
		t.Fatal("VFS unregister terminal state not retained")
	}
	if !lifecycleVFSFound(t, binding.vfs, name) {
		t.Fatal("VFS disappeared despite unregister failure")
	}
	if err := session.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("repeat VFS unregister session close=%v", err)
	}
	if got := captureTerminalSnapshot(t, lease, binding, observer, name); got != first {
		t.Fatalf("repeat VFS unregister close changed retained snapshot: first=%+v second=%+v", first, got)
	}
	storeVFSUnregister = original
	if err := binding.vfs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedFDBad(t, rootFD)
	assertLifecycleBalanced(t, observer)
}

func newTerminalBinding(t *testing.T) (*rootLease, *sqlBinding, *storeProofObserver) {
	t.Helper()
	lease, _ := newLifecycleLeaseMode(t, storeEnroll)
	observer := &storeProofObserver{}
	binding, err := openSQLBinding(context.WithValue(context.Background(), storeProofObserverKey{}, observer), lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	return lease, binding, observer
}

func lifecycleOpenExtraFile(t *testing.T, binding *sqlBinding) (uintptr, string) {
	t.Helper()
	name, err := libc.CString(binding.vfs.main)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(binding.vfs.tls, name)
	file := libc.Xmalloc(binding.vfs.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if file == 0 {
		t.Fatal("extra file allocation")
	}
	if got := storeVFSOpen(binding.vfs.tls, binding.vfs.vfs, name, file, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READWRITE, 0); got != sqlite3.SQLITE_OK {
		libc.Xfree(binding.vfs.tls, file)
		t.Fatalf("extra xOpen=%d", got)
	}
	return file, binding.vfs.name
}

func lifecycleVFSFound(t *testing.T, v *storeVFS, name string) bool {
	t.Helper()
	cname, err := libc.CString(name)
	if err != nil {
		t.Fatal(err)
	}
	defer libc.Xfree(v.tls, cname)
	return sqlite3.Xsqlite3_vfs_find(v.tls, cname) != 0
}

func assertOwnedFDBad(t *testing.T, fd int) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("owned fd=%d state err=%v want EBADF", fd, err)
	}
}

type terminalSnapshot struct {
	vfsFound, registryPresent, leaseValid, rootFDLive  bool
	tlsCreates, tlsCloses, rootFDs, rootFDCloses       int
	vfsOpens, vfsCloses, physicalOpens, physicalCloses int
	allocs, frees, registers, unregisters              int
	openFiles, closeErrors                             int64
}

func assertTerminalRetained(t *testing.T, lease *rootLease, binding *sqlBinding, observer *storeProofObserver, name string) terminalSnapshot {
	t.Helper()
	snapshot := captureTerminalSnapshot(t, lease, binding, observer, name)
	if !snapshot.leaseValid || !snapshot.rootFDLive {
		t.Fatalf("terminal owner resources not retained: %+v", snapshot)
	}
	fresh, err := openRootLease(context.Background(), lease.path, storeRefresh)
	if fresh != nil || !errors.Is(err, ErrRefreshConflict) {
		t.Fatalf("fresh EX while terminal owner retained lease=%v err=%v", fresh, err)
	}
	return snapshot
}

func captureTerminalSnapshot(t *testing.T, lease *rootLease, binding *sqlBinding, observer *storeProofObserver, name string) terminalSnapshot {
	t.Helper()
	c := (*vfsContext)(libcPtr(binding.vfs.ctx))
	observer.mu.Lock()
	snapshot := terminalSnapshot{
		tlsCreates: observer.tlsCreates, tlsCloses: observer.tlsCloses,
		rootFDs: observer.rootFDs, rootFDCloses: observer.rootFDCloses,
		vfsOpens: observer.vfsOpens, vfsCloses: observer.vfsCloses,
		physicalOpens: observer.physicalOpens, physicalCloses: observer.physicalCloses,
		allocs: observer.allocs, frees: observer.frees,
		registers: observer.registers, unregisters: observer.unregisters,
	}
	observer.mu.Unlock()
	snapshot.openFiles = atomic.LoadInt64(&c.openFiles)
	snapshot.closeErrors = atomic.LoadInt64(&c.closeErrors)
	snapshot.vfsFound = lifecycleVFSFound(t, binding.vfs, name)
	snapshot.registryPresent = storeVFSObserverFor(c) == observer
	snapshot.leaseValid = lease.valid()
	_, err := unix.FcntlInt(uintptr(lease.fd), unix.F_GETFD, 0)
	snapshot.rootFDLive = err == nil
	return snapshot
}

func captureTerminalSnapshotDetached(t *testing.T, lease *rootLease, name string, observer *storeProofObserver) terminalSnapshot {
	t.Helper()
	observer.mu.Lock()
	snapshot := terminalSnapshot{
		tlsCreates: observer.tlsCreates, tlsCloses: observer.tlsCloses,
		rootFDs: observer.rootFDs, rootFDCloses: observer.rootFDCloses,
		vfsOpens: observer.vfsOpens, vfsCloses: observer.vfsCloses,
		physicalOpens: observer.physicalOpens, physicalCloses: observer.physicalCloses,
		allocs: observer.allocs, frees: observer.frees,
		registers: observer.registers, unregisters: observer.unregisters,
	}
	observer.mu.Unlock()
	tls := libc.NewTLS()
	defer tls.Close()
	cname, err := libc.CString(name)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.vfsFound = sqlite3.Xsqlite3_vfs_find(tls, cname) != 0
	libc.Xfree(tls, cname)
	snapshot.leaseValid = lease.valid()
	_, err = unix.FcntlInt(uintptr(lease.fd), unix.F_GETFD, 0)
	snapshot.rootFDLive = err == nil
	return snapshot
}

func TestStoreLifecycleLIFE01ConstructionFailures(t *testing.T) {
	for _, phase := range []string{
		"vfs.tls", "vfs.ctx", "vfs.methods", "vfs.vfs", "vfs.name", "vfs.register",
		"driver.open", "db.Conn", "conn.ATTACHED",
		"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF",
		"exec:PRAGMA query_only=ON", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL",
		"query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema", "query:PRAGMA query_only",
		"query:PRAGMA journal_mode", "query:PRAGMA synchronous",
	} {
		t.Run(phase, func(t *testing.T) {
			lease, root := newLifecycleLease(t)
			if isSetupPhase(phase) {
				_ = lease.Close()
				t.Skip("conditional setup matrix below")
			}
			observer := &storeProofObserver{failPhase: phase}
			ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
			binding, err := openSQLBinding(ctx, lease, storeEnroll)
			if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("phase=%s binding=%v err=%v", phase, binding, err)
			}
			assertLifecycleBalanced(t, observer)
			assertLifecycleCheckpoint(t, observer, phase, 1, 0, 0)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_ = root
		})
	}
	for _, phase := range []string{"exec:PRAGMA query_only=ON", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL", "query:PRAGMA query_only", "query:PRAGMA journal_mode", "query:PRAGMA synchronous"} {
		for _, mode := range []storeMode{storeRead, storeEnroll} {
			t.Run(phase+map[storeMode]string{storeRead: "-read", storeEnroll: "-writer"}[mode], func(t *testing.T) {
				if !phaseApplies(phase, mode) {
					t.Skip("conditional setup phase")
				}
				lease, _ := newLifecycleLeaseMode(t, mode)
				observer := &storeProofObserver{failPhase: phase}
				ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
				binding, err := openSQLBinding(ctx, lease, mode)
				if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("mode=%d phase=%s binding=%v err=%v", mode, phase, binding, err)
				}
				assertLifecycleBalanced(t, observer)
				assertLifecycleCheckpoint(t, observer, phase, 1, 0, 0)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, phase := range []string{
		"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF",
		"query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema",
	} {
		for _, mode := range []storeMode{storeRead, storeEnroll} {
			t.Run(phase+map[storeMode]string{storeRead: "-read", storeEnroll: "-writer"}[mode], func(t *testing.T) {
				lease, _ := newLifecycleLeaseMode(t, mode)
				observer := &storeProofObserver{failPhase: phase}
				ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
				binding, err := openSQLBinding(ctx, lease, mode)
				if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("mode=%d phase=%s binding=%v err=%v", mode, phase, binding, err)
				}
				assertLifecycleCheckpoint(t, observer, phase, 1, 0, 0)
				assertLifecycleBalanced(t, observer)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, after := range []bool{false, true} {
		t.Run("main-open"+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
			if after {
				testMainOpenAfter(t)
				return
			}
			lease, root := newLifecycleLease(t)
			if err := os.Remove(filepath.Join(root, storeDBName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observer := &storeProofObserver{ctx: ctx, cancel: cancel, failPhase: "main-open", cancelPhase: "main-open", cancelAfter: after}
			ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
			binding, err := openSQLBinding(ctx, lease, storeEnroll)
			if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("main-open binding=%v err=%v", binding, err)
			}
			assertLifecycleBalanced(t, observer)
			assertLifecycleCheckpoint(t, observer, "main-open", 1, boolInt(after), boolInt(after))
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, phase := range []string{"root-open", "ancestor-open-0", "ancestor-open-1"} {
		t.Run(phase, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			observer := &storeProofObserver{failPhase: phase}
			ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
			lease, err := openRootLease(ctx, filepath.Join(base, "one", "two", "store"), storeEnroll)
			if lease != nil || !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("phase=%s lease=%v err=%v", phase, lease, err)
			}
			assertLifecycleCheckpoint(t, observer, phase, 1, 0, 0)
			assertLifecycleBalanced(t, observer)
			if err := os.Chmod(base, 0o700); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testMainOpenAfter(t *testing.T) {
	t.Helper()
	lease, _ := newLifecycleLeaseMode(t, storeRead)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelPhase: "main-open", cancelAfter: true}
	v, err := newStoreVFSObserved(lease, storeEnroll, observer)
	if err != nil {
		t.Fatal(err)
	}
	name := nsCString(t, v.main, v.tls)
	defer libc.Xfree(v.tls, name)
	p := libc.Xmalloc(v.tls, types.Size_t(unsafe.Sizeof(vfsFile{})))
	if p == 0 {
		t.Fatal("file allocation")
	}
	got := storeVFSOpen(v.tls, v.vfs, name, p, sqlite3.SQLITE_OPEN_MAIN_DB|sqlite3.SQLITE_OPEN_READONLY, 0)
	if got != sqlite3.SQLITE_CANTOPEN {
		t.Fatalf("main open after cancellation=%d", got)
	}
	assertLifecycleCheckpoint(t, observer, "main-open", 1, 1, 1)
	libc.Xfree(v.tls, p)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	assertLifecycleBalanced(t, observer)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreLifecycleLIFE02CancellationBoundaries(t *testing.T) {
	phases := []string{
		"vfs.tls", "vfs.ctx", "vfs.methods", "vfs.vfs", "vfs.name", "vfs.register",
		"driver.open", "db.Conn", "conn.ATTACHED",
		"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF",
		"exec:PRAGMA query_only=ON", "query:PRAGMA temp_store", "query:PRAGMA mmap_size",
		"query:PRAGMA trusted_schema", "query:PRAGMA query_only",
	}
	for _, phase := range phases {
		if isSetupPhase(phase) {
			continue
		}
		for _, after := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
				lease, _ := newLifecycleLease(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelPhase: phase, cancelAfter: after}
				ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
				binding, err := openSQLBinding(ctx, lease, storeEnroll)
				if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("phase=%s after=%v binding=%v err=%v", phase, after, binding, err)
				}
				assertLifecycleCheckpoint(t, observer, phase, 1, boolInt(after), 1)
				assertLifecycleBalanced(t, observer)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, phase := range []string{
		"exec:PRAGMA temp_store=MEMORY", "exec:PRAGMA mmap_size=0", "exec:PRAGMA trusted_schema=OFF",
		"query:PRAGMA temp_store", "query:PRAGMA mmap_size", "query:PRAGMA trusted_schema",
	} {
		for _, mode := range []storeMode{storeRead, storeEnroll} {
			for _, after := range []bool{false, true} {
				t.Run(phase+map[storeMode]string{storeRead: "-read", storeEnroll: "-writer"}[mode]+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
					lease, _ := newLifecycleLeaseMode(t, mode)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelPhase: phase, cancelAfter: after}
					ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
					binding, err := openSQLBinding(ctx, lease, mode)
					if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
						t.Fatalf("mode=%d phase=%s after=%v binding=%v err=%v", mode, phase, after, binding, err)
					}
					assertLifecycleCheckpoint(t, observer, phase, 1, boolInt(after), 1)
					assertLifecycleBalanced(t, observer)
					if err := lease.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
	for _, phase := range []string{"exec:PRAGMA query_only=ON", "exec:PRAGMA journal_mode=DELETE", "exec:PRAGMA synchronous=FULL", "query:PRAGMA query_only", "query:PRAGMA journal_mode", "query:PRAGMA synchronous"} {
		for _, mode := range []storeMode{storeRead, storeEnroll} {
			for _, after := range []bool{false, true} {
				t.Run(phase+map[storeMode]string{storeRead: "-read", storeEnroll: "-writer"}[mode]+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
					if !phaseApplies(phase, mode) {
						t.Skip("conditional setup phase")
					}
					lease, _ := newLifecycleLeaseMode(t, mode)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelPhase: phase, cancelAfter: after}
					ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
					binding, err := openSQLBinding(ctx, lease, mode)
					if binding != nil || !errors.Is(err, ErrProvenanceUnavailable) {
						t.Fatalf("mode=%d phase=%s after=%v binding=%v err=%v", mode, phase, after, binding, err)
					}
					assertLifecycleBalanced(t, observer)
					assertLifecycleCheckpoint(t, observer, phase, 1, boolInt(after), 1)
					if err := lease.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
	for _, phase := range []string{"root-open", "ancestor-open-0", "ancestor-open-1"} {
		for _, after := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
				base, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				root := filepath.Join(base, "one", "two", "store")
				if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
					t.Fatal(err)
				}
				seed, err := openRootLease(context.Background(), root, storeEnroll)
				if err != nil {
					t.Fatal(err)
				}
				if err := seed.Close(); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelPhase: phase, cancelAfter: after}
				ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
				before := openFDCount(t)
				lease, err := openRootLease(ctx, root, storeEnroll)
				if lease != nil || !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("phase=%s after=%v lease=%v err=%v", phase, after, lease, err)
				}
				assertLifecycleCheckpoint(t, observer, phase, 1, boolInt(after), 1)
				assertLifecycleBalanced(t, observer)
				if got := openFDCount(t); got != before {
					t.Fatalf("phase=%s after=%v FD count=%d want=%d", phase, after, got, before)
				}
				fresh, err := openRootLease(context.Background(), root, storeRefresh)
				if err != nil {
					t.Fatalf("phase=%s fresh EX: %v", phase, err)
				}
				if err := fresh.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStoreLifecycleJournalOpenBoundaries(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure-before", true: "cancel-after"}[after], func(t *testing.T) {
			lease, root := newLifecycleLease(t)
			if err := os.Remove(filepath.Join(root, storeDBName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observer := &storeProofObserver{ctx: ctx, cancel: cancel, cancelAfter: after, cancelPhase: "journal-open"}
			if !after {
				observer.failPhase = "journal-open"
			}
			ctx = context.WithValue(ctx, storeProofObserverKey{}, observer)
			binding, err := openSQLBinding(ctx, lease, storeEnroll)
			if err != nil {
				t.Fatalf("binding construction: %v", err)
			}
			if _, err := binding.conn.ExecContext(ctx, "CREATE TABLE lifecycle_journal(v INTEGER)"); err == nil {
				t.Fatal("journal-open fault was not observed")
			}
			assertLifecycleCheckpoint(t, observer, "journal-open", 1, boolInt(after), boolInt(after))
			// storeVFS.Close refuses while any VFS file is still open, so a
			// successful binding Close proves the failed xOpen left openFiles=0.
			// The counter itself lives in libc memory that Close frees; reading
			// it afterwards is a use-after-free (it faults on Linux).
			if err := binding.Close(); err != nil {
				t.Fatalf("journal-open after failed xOpen left the VFS busy: %v", err)
			}
			assertLifecycleBalanced(t, observer)
			assertLifecycleBalanced(t, observer)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newLifecycleLease(t *testing.T) (*rootLease, string) {
	return newLifecycleLeaseMode(t, storeEnroll)
}

func newLifecycleLeaseMode(t *testing.T, mode storeMode) (*rootLease, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	lease, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, storeDBName), nil, 0o600); err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if mode == storeEnroll {
		if err := os.Remove(filepath.Join(root, storeDBName)); err != nil {
			t.Fatal(err)
		}
	}
	if mode != storeEnroll {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		lease, err = openRootLease(context.Background(), root, mode)
		if err != nil {
			t.Fatal(err)
		}
	}
	return lease, root
}

func assertLifecycleBalanced(t *testing.T, observer *storeProofObserver) {
	t.Helper()
	observer.mu.Lock()
	allocs, frees, registers, unregisters := observer.allocs, observer.frees, observer.registers, observer.unregisters
	observer.mu.Unlock()
	if allocs != frees {
		t.Fatalf("allocation ledger allocs=%d frees=%d", allocs, frees)
	}
	if registers != unregisters {
		t.Fatalf("registration ledger registers=%d unregisters=%d", registers, unregisters)
	}
	if observer.tlsCreates != observer.tlsCloses || observer.rootFDs != observer.rootFDCloses || observer.vfsOpens != observer.vfsCloses || observer.physicalOpens != observer.physicalCloses {
		t.Fatalf("resource ledger tls=%d/%d rootfd=%d/%d vfsfile=%d/%d physical=%d/%d", observer.tlsCreates, observer.tlsCloses, observer.rootFDs, observer.rootFDCloses, observer.vfsOpens, observer.vfsCloses, observer.physicalOpens, observer.physicalCloses)
	}
}

func isSetupPhase(phase string) bool {
	return len(phase) >= 5 && (phase[:5] == "exec:" || len(phase) >= 6 && phase[:6] == "query:")
}

func phaseApplies(phase string, mode storeMode) bool {
	if strings.Contains(phase, "query_only") {
		return mode == storeRead
	}
	if strings.Contains(phase, "journal_mode") || strings.Contains(phase, "synchronous") {
		return mode != storeRead
	}
	return true
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func assertLifecycleCheckpoint(t *testing.T, observer *storeProofObserver, phase string, wantBefore, wantAfter, wantCancel int) {
	t.Helper()
	observer.mu.Lock()
	hits := observer.hits[phase]
	cancels := observer.cancelHits[phase]
	observer.mu.Unlock()
	if hits[0] != wantBefore || hits[1] != wantAfter || cancels[0]+cancels[1] != wantCancel {
		t.Fatalf("phase=%s hits before/after=%d/%d want=%d/%d cancel=%d want=%d", phase, hits[0], hits[1], wantBefore, wantAfter, cancels[0]+cancels[1], wantCancel)
	}
}
