//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestStoreRecoveryBorrowCloseWaitsForOwner(t *testing.T) {
	lease, root, observer := newRecoveryLeaseForTest(t)
	rootFD := lease.fd
	before := recoveryLeaseIdentity(t, rootFD)
	observer.mu.Lock()
	closesBefore := observer.rootFDCloses
	observer.mu.Unlock()
	borrow, err := lease.beginStoreRecoveryBorrow(context.Background())
	if err != nil {
		t.Fatalf("begin recovery borrow: %v", err)
	}
	if _, err := lease.beginStoreRecoveryBorrow(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("concurrent recovery borrow=%v", err)
	}

	closeResults := make(chan error, 2)
	go func() { closeResults <- lease.Close() }()
	go func() { closeResults <- lease.Close() }()
	waitRecoveryCloseRequest(t, lease)
	select {
	case err := <-closeResults:
		t.Fatalf("Close returned while borrow was active: %v", err)
	default:
	}
	if err := borrow.check(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("checkpoint after Close request=%v", err)
	}
	if got := recoveryLeaseIdentity(t, rootFD); got != before {
		t.Fatalf("root FD identity changed during borrow: got=%+v want=%+v", got, before)
	}
	if contender, err := openRootLease(context.Background(), root, storeRead); contender != nil || !errors.Is(err, ErrPending) {
		t.Fatalf("SH contender while EX borrow lease=%v err=%v", contender, err)
	}
	if contender, err := openRootLease(context.Background(), root, storeRefresh); contender != nil || !errors.Is(err, ErrRefreshConflict) {
		t.Fatalf("EX contender while EX borrow lease=%v err=%v", contender, err)
	}

	borrow.abort()
	for i := 0; i != 2; i++ {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close[%d]=%v", i, err)
		}
	}
	assertRecoveryFDEBADF(t, rootFD)
	observer.mu.Lock()
	closes := observer.rootFDCloses
	observer.mu.Unlock()
	if closes != closesBefore+1 {
		t.Fatalf("root descriptor close delta=%d, want 1", closes-closesBefore)
	}
	if fresh, err := openRootLease(context.Background(), root, storeRead); err != nil {
		t.Fatalf("SH contender did not acquire after safe close: %v", err)
	} else if err := fresh.Close(); err != nil {
		t.Fatalf("close fresh SH contender: %v", err)
	}
}

func TestStoreRecoveryBorrowCancellationAndFinishPublication(t *testing.T) {
	t.Run("cancellation vetoes pre-unlink authorization", func(t *testing.T) {
		lease, _, _ := newRecoveryLeaseForTest(t)
		rootFD := lease.fd
		borrow, err := lease.beginStoreRecoveryBorrow(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := borrow.authorizeUnlink(ctx); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("cancelled pre-unlink authorization=%v", err)
		}
		borrow.abort()
		if err := lease.Close(); err != nil {
			t.Fatalf("close after cancelled operation: %v", err)
		}
		assertRecoveryFDEBADF(t, rootFD)
	})

	t.Run("close request vetoes final publication", func(t *testing.T) {
		lease, _, _ := newRecoveryLeaseForTest(t)
		rootFD := lease.fd
		borrow, err := lease.beginStoreRecoveryBorrow(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- lease.Close() }()
		waitRecoveryCloseRequest(t, lease)
		if err := borrow.finish(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("finish after Close request=%v", err)
		}
		if err := <-result; err != nil {
			t.Fatalf("waiting Close=%v", err)
		}
		assertRecoveryFDEBADF(t, rootFD)
	})
}

func TestStoreRecoveryBorrowCloseCannotWinDuringCapabilityCapture(t *testing.T) {
	lease, _, _ := newRecoveryLeaseForTest(t)
	rootFD := lease.fd
	originalHook := storeRecoveryBorrowHook
	t.Cleanup(func() { storeRecoveryBorrowHook = originalHook })
	entered := make(chan struct{})
	release := make(chan struct{})
	storeRecoveryBorrowHook = func(stage string) {
		if stage != "started-before-capability" {
			return
		}
		close(entered)
		<-release
	}
	beginResult := make(chan error, 1)
	go func() {
		_, err := lease.beginStoreRecoveryBorrow(context.Background())
		beginResult <- err
	}()
	<-entered
	closeResult := make(chan error, 1)
	go func() { closeResult <- lease.Close() }()
	waitRecoveryCloseRequest(t, lease)
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned during capability capture: %v", err)
	default:
	}
	close(release)
	if err := <-beginResult; !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("begin after Close request=%v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close after failed begin=%v", err)
	}
	assertRecoveryFDEBADF(t, rootFD)
}

func TestStoreRecoveryBorrowTerminalRetainsActualVFSAndRoot(t *testing.T) {
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
		_ = seed.Close()
		t.Fatal(err)
	}
	if _, err := seedBinding.conn.ExecContext(context.Background(), "CREATE TABLE recovery_lease_terminal(v INTEGER)"); err != nil {
		_ = seedBinding.Close()
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := seedBinding.Close(); err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	observer := &storeProofObserver{}
	recoveryCtx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	lease, err := openRootLease(recoveryCtx, root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	rootFD := lease.fd
	borrow, err := lease.beginStoreRecoveryBorrow(context.Background())
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	binding, err := openSQLBinding(recoveryCtx, lease, storeRecover)
	if err != nil {
		borrow.abort()
		_ = lease.Close()
		t.Fatal(err)
	}

	originalUnregister := storeVFSUnregister
	storeVFSUnregister = func(tls *libc.TLS, vfs uintptr) int32 { return sqlite3.SQLITE_BUSY }
	t.Cleanup(func() { storeVFSUnregister = originalUnregister })
	closeResult := make(chan error, 1)
	go func() { closeResult <- lease.Close() }()
	waitRecoveryCloseRequest(t, lease)
	if err := binding.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("injected retained binding close=%v", err)
	}
	if binding.closed || binding.closeErr == nil || binding.vfs.closed {
		t.Fatalf("binding/VFS was not retained after failed teardown")
	}
	terminalOwner, err := newStoreRecoveryTerminalOwner(binding, -1, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	borrow.retainTerminal(terminalOwner, binding.closeErr)
	if err := <-closeResult; !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("Close did not wake with terminal failure: %v", err)
	}
	// The recovery stack now drops all local owner references.  The root lease
	// must be the only path retaining the actual binding/VFS after a terminal
	// teardown error.
	binding = nil       //nolint:wastedassign // drop the reference before runtime.GC()
	terminalOwner = nil //nolint:ineffassign,wastedassign // drop the reference before runtime.GC()
	runtime.GC()
	lease.mu.Lock()
	retained := lease.recoveryTerminalOwner
	lease.mu.Unlock()
	if retained == nil || retained.binding == nil || retained.binding.vfs == nil || retained.binding.vfs.closed || retained.journalFD != -1 || retained.journalCloseAttempted {
		t.Fatalf("root lease lost or changed terminal owner after unwind: %+v", retained)
	}
	retained.mu.Lock()
	transferred := retained.transferred
	retained.mu.Unlock()
	if !transferred {
		t.Fatal("terminal owner was not transferred into root lease")
	}
	if !lifecycleVFSFound(t, retained.binding.vfs, retained.binding.vfs.name) {
		t.Fatal("retained terminal VFS callback registration was freed")
	}
	if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
		t.Fatalf("terminal root FD was released: %v", err)
	}
	if contender, err := openRootLease(context.Background(), root, storeRefresh); contender != nil || !errors.Is(err, ErrRefreshConflict) {
		t.Fatalf("EX contender acquired while terminal owner retained root: lease=%v err=%v", contender, err)
	}

	storeVFSUnregister = originalUnregister
	releaseRecoveryTerminalFixture(t, lease)
	assertRecoveryFDEBADF(t, rootFD)
}

func TestStoreRecoveryBorrowRejectsInvalidCapability(t *testing.T) {
	t.Run("closed lease", func(t *testing.T) {
		lease, _, _ := newRecoveryLeaseForTest(t)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if borrow, err := lease.beginStoreRecoveryBorrow(context.Background()); borrow != nil || !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("borrow on closed lease=%v err=%v", borrow, err)
		}
	})

	t.Run("replaced locator before start", func(t *testing.T) {
		lease, root, _ := newRecoveryLeaseForTest(t)
		if err := os.Rename(root, root+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if borrow, err := lease.beginStoreRecoveryBorrow(context.Background()); borrow != nil || !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("borrow on replaced locator=%v err=%v", borrow, err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("closed and reused descriptor before start", func(t *testing.T) {
		lease, _, _ := newRecoveryLeaseForTest(t)
		rootFD := lease.fd
		source, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup2(source, rootFD); err != nil {
			_ = unix.Close(source)
			t.Fatal(err)
		}
		if err := unix.Close(source); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(rootFD)
		if borrow, err := lease.beginStoreRecoveryBorrow(context.Background()); borrow != nil || !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("borrow on reused descriptor=%v err=%v", borrow, err)
		}
	})

	t.Run("captured capability is revalidated", func(t *testing.T) {
		lease, root, _ := newRecoveryLeaseForTest(t)
		borrow, err := lease.beginStoreRecoveryBorrow(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if borrow.capability.fd != lease.fd || borrow.capability.dev != lease.dev || borrow.capability.ino != lease.ino {
			t.Fatalf("borrow did not capture root capability: %+v lease=%d/%d/%d", borrow.capability, lease.fd, lease.dev, lease.ino)
		}
		if err := os.Rename(root, root+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := borrow.check(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("checkpoint after locator replacement=%v", err)
		}
		borrow.abort()
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

type recoveryRootIdentity struct{ dev, ino uint64 }

func recoveryLeaseIdentity(t *testing.T, fd int) recoveryRootIdentity {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat root FD %d: %v", fd, err)
	}
	return recoveryRootIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
}

func assertRecoveryFDEBADF(t *testing.T, fd int) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("root FD %d after close error=%v, want EBADF", fd, err)
	}
}

// releaseRecoveryTerminalFixture is deliberately test-only forensic cleanup.
// Production Close must keep a terminal owner stable and must never retry it.
// The fixture first proves that rootLease still owns the retained binding/VFS,
// then quiesces that exact owner and finally releases the test root descriptor.
func releaseRecoveryTerminalFixture(t *testing.T, lease *rootLease) {
	t.Helper()
	lease.mu.Lock()
	owner := lease.recoveryTerminalOwner
	terminal := lease.recoveryTerminal
	fd := lease.fd
	lease.mu.Unlock()
	if !terminal || owner == nil || owner.binding == nil || owner.binding.vfs == nil || owner.journalFD != -1 {
		t.Fatalf("fixture terminal owner is not quiescence-eligible: terminal=%v owner=%+v", terminal, owner)
	}
	if err := owner.binding.vfs.Close(); err != nil {
		t.Fatalf("fixture retained VFS cleanup: %v", err)
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatalf("fixture terminal unlock: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("fixture terminal close: %v", err)
	}
}

func waitRecoveryCloseRequest(t *testing.T, lease *rootLease) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lease.mu.Lock()
		requested := lease.recoveryCloseRequested
		lease.mu.Unlock()
		if requested {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Close did not record recovery close request")
}

func newRecoveryLeaseForTest(t *testing.T) (*rootLease, string, *storeProofObserver) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "store")
	seed, err := openRootLease(context.Background(), root, storeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	observer := &storeProofObserver{}
	ctx := context.WithValue(context.Background(), storeProofObserverKey{}, observer)
	lease, err := openRootLease(ctx, root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	return lease, root, observer
}
