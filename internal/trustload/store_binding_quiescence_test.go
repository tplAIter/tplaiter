//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestStoreBindingCloseWaitsForActualSQLiteRows proves the production lifetime
// bridge: sqlBinding.Close reaches sql.Conn.Close before VFS teardown, and the
// latter does not run while an actual SQLite Rows operation still owns the
// connection.  The physical-close seam synchronizes only the start of Close;
// the held operation is real SQLite work through the registered VFS.
func TestStoreBindingCloseWaitsForActualSQLiteRows(t *testing.T) {
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
	proof := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, proof)
	binding, err := openSQLBinding(ctx, lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if _, err := binding.conn.ExecContext(ctx, "CREATE TABLE quiescence(v INTEGER); INSERT INTO quiescence VALUES(7)"); err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	rows, err := binding.conn.QueryContext(ctx, "SELECT v FROM quiescence")
	if err != nil {
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if !rows.Next() {
		_ = rows.Close()
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal("actual SQLite Rows produced no value")
	}
	var value int
	if err := rows.Scan(&value); err != nil || value != 7 {
		_ = rows.Close()
		_ = binding.Close()
		_ = lease.Close()
		t.Fatalf("actual SQLite row value=%d err=%v", value, err)
	}

	c := (*vfsContext)(libcPtr(binding.vfs.ctx))
	if atomic.LoadInt64(&c.callbackCounts[callbackRead]) == 0 {
		_ = rows.Close()
		_ = binding.Close()
		_ = lease.Close()
		t.Fatal("held SQLite operation did not enter the VFS read callback")
	}
	token, name := c.token, binding.vfs.name
	started := make(chan struct{})
	originalPhysicalClose := storePhysicalClose
	storePhysicalClose = func(conn *sql.Conn) error {
		close(started)
		return originalPhysicalClose(conn)
	}
	t.Cleanup(func() { storePhysicalClose = originalPhysicalClose })
	closed := make(chan error, 1)
	go func() { closed <- binding.Close() }()
	<-started
	select {
	case err := <-closed:
		t.Fatalf("binding.Close returned while actual Rows remained open: %v", err)
	default:
	}
	binding.vfs.mu.Lock()
	vfsClosed := binding.vfs.closed
	binding.vfs.mu.Unlock()
	proof.mu.Lock()
	allocs, frees, registers, unregisters, tlsCreates, tlsCloses := proof.allocs, proof.frees, proof.registers, proof.unregisters, proof.tlsCreates, proof.tlsCloses
	proof.mu.Unlock()
	if vfsClosed || frees != 0 || unregisters != 0 || !lifecycleVFSFound(t, binding.vfs, name) {
		t.Fatalf("VFS storage changed before Rows release: closed=%v allocs=%d frees=%d registers=%d unregisters=%d", vfsClosed, allocs, frees, registers, unregisters)
	}
	storeVFSObserverRegistry.RLock()
	_, registered := storeVFSObserverRegistry.byToken[token]
	storeVFSObserverRegistry.RUnlock()
	if !registered || tlsCreates != 1 || tlsCloses != 0 {
		t.Fatalf("callback/TLS retained state before Rows release registered=%v tls=%d/%d", registered, tlsCreates, tlsCloses)
	}

	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("binding.Close after Rows release: %v", err)
	}
	binding.vfs.mu.Lock()
	vfsClosed = binding.vfs.closed
	binding.vfs.mu.Unlock()
	proof.mu.Lock()
	allocs, frees, registers, unregisters, tlsCreates, tlsCloses = proof.allocs, proof.frees, proof.registers, proof.unregisters, proof.tlsCreates, proof.tlsCloses
	proof.mu.Unlock()
	storeVFSObserverRegistry.RLock()
	_, registered = storeVFSObserverRegistry.byToken[token]
	storeVFSObserverRegistry.RUnlock()
	if !vfsClosed || allocs != 4 || frees != 4 || registers != 1 || unregisters != 1 || tlsCreates != 1 || tlsCloses != 1 || registered {
		t.Fatalf("post-release VFS lifecycle closed=%v allocs=%d frees=%d registers=%d unregisters=%d tls=%d/%d registered=%v", vfsClosed, allocs, frees, registers, unregisters, tlsCreates, tlsCloses, registered)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}
