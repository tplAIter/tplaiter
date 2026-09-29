//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// TestStoreColdTerminalC04PostUnlinkCancellationAndClose proves the mutation
// boundary rather than merely observing the resulting missing path.  The real
// helper unlinks the real sidecar; the directory-sync seam then requests both
// cancellation and Close.  The helper must still issue the sync, absence and
// owned-FD teardown steps, but may not publish a successful recovery.
func TestStoreColdTerminalC04PostUnlinkCancellationAndClose(t *testing.T) {
	root := newColdRecoveryRoot(t, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}

	originalSync, originalFstatat, originalClose := storeSyncDirectory, storeRecoveryFstatat, storeRecoveryClose
	t.Cleanup(func() {
		storeSyncDirectory, storeRecoveryFstatat, storeRecoveryClose = originalSync, originalFstatat, originalClose
	})
	var syncCalls, absenceCalls, journalCloseCalls int
	closeResult := make(chan error, 1)
	storeSyncDirectory = func(fd int) error {
		syncCalls++
		cancel()
		go func() { closeResult <- lease.Close() }()
		waitRecoveryCloseRequest(t, lease)
		return originalSync(fd)
	}
	storeRecoveryFstatat = func(fd int, name string, st *unix.Stat_t, flags int) error {
		if name == storeDBName+"-journal" {
			absenceCalls++
		}
		return originalFstatat(fd, name, st, flags)
	}
	storeRecoveryClose = func(fd int) error {
		journalCloseCalls++
		return originalClose(fd)
	}

	err = recoverStoreColdJournal(ctx, lease)
	if !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("recover after post-unlink cancellation/Close = %v, want typed failure", err)
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("waiting Close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after post-unlink recovery quiesced")
	}
	if syncCalls != 1 || absenceCalls < 2 || journalCloseCalls != 2 {
		t.Fatalf("post-unlink terminal steps sync=%d absence=%d journalClose=%d; want sync=1 absence>=2 close=2", syncCalls, absenceCalls, journalCloseCalls)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(err) {
		t.Fatalf("post-unlink sidecar state = %v, want absent", err)
	}
}

// TestStoreColdTerminalC05TerminalOwners exercises terminal ownership after
// actual inspection and/or actual SQLite binding setup.  Each injected error
// is returned only after the real syscall/teardown attempt; it cannot invent
// a healthy database, journal identity, or successful unlink.
func TestStoreColdTerminalC05TerminalOwners(t *testing.T) {
	t.Run("preFD-close", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		original := storeRecoveryClose
		calls := 0
		storeRecoveryClose = func(fd int) error {
			calls++
			err := original(fd)
			if calls == 1 && err == nil {
				return unix.EIO
			}
			return err
		}
		t.Cleanup(func() { storeRecoveryClose = original })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		coldTerminalExpectRetained(t, root, lease, false)
		if calls != 1 {
			t.Fatalf("pre-FD close attempts=%d want=1", calls)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
			t.Fatalf("pre-FD failure mutated journal: %v", err)
		}
		coldTerminalForensicRelease(t, lease)
	})
	t.Run("postFD-close", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		original := storeRecoveryClose
		calls := 0
		storeRecoveryClose = func(fd int) error {
			calls++
			err := original(fd)
			if calls == 2 && err == nil {
				return unix.EIO
			}
			return err
		}
		t.Cleanup(func() { storeRecoveryClose = original })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		coldTerminalExpectRetained(t, root, lease, false)
		if calls != 2 {
			t.Fatalf("post-FD close attempts=%d want=2", calls)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(err) {
			t.Fatalf("post-FD terminal state = %v, want absent", err)
		}
		coldTerminalForensicRelease(t, lease)
	})
	t.Run("recovery-binding-close", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		original := storePhysicalClose
		calls := 0
		storePhysicalClose = func(conn *sql.Conn) error {
			calls++
			if err := original(conn); err != nil {
				return err
			}
			return unix.EIO
		}
		t.Cleanup(func() { storePhysicalClose = original })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		coldTerminalExpectRetained(t, root, lease, true)
		if calls != 1 {
			t.Fatalf("recovery binding close attempts=%d want=1", calls)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
			t.Fatalf("binding-close failure mutated journal: %v", err)
		}
		coldTerminalForensicRelease(t, lease)
	})
	t.Run("VFS-unregister", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		original := storeVFSUnregister
		storeVFSUnregister = func(*libc.TLS, uintptr) int32 { return sqlite3.SQLITE_BUSY }
		t.Cleanup(func() { storeVFSUnregister = original })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		coldTerminalExpectRetained(t, root, lease, true)
		lease.mu.Lock()
		owner := lease.recoveryTerminalOwner
		lease.mu.Unlock()
		if owner == nil || owner.binding == nil || owner.binding.vfs == nil || owner.binding.vfs.closed || !lifecycleVFSFound(t, owner.binding.vfs, owner.binding.vfs.name) {
			t.Fatalf("VFS unregister error did not retain actual VFS/TLS owner: %+v", owner)
		}
		storeVFSUnregister = original
		coldTerminalForensicRelease(t, lease)
	})
}

func coldTerminalExpectRetained(t *testing.T, root string, lease *rootLease, wantBinding bool) {
	t.Helper()
	rootFD := lease.fd
	if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("recovery terminal error = %v", err)
	}
	first := lease.Close()
	second := lease.Close()
	if first == nil || second == nil || !errors.Is(first, second) {
		t.Fatalf("repeated terminal Close first=%v second=%v", first, second)
	}
	if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
		t.Fatalf("terminal root FD was prematurely closed/reused: %v", err)
	}
	if contender, err := openRootLease(context.Background(), root, storeRefresh); contender != nil || !errors.Is(err, ErrRefreshConflict) {
		if contender != nil {
			_ = contender.Close()
		}
		t.Fatalf("terminal owner released root EX lock: lease=%v err=%v", contender, err)
	}
	lease.mu.Lock()
	owner, terminal := lease.recoveryTerminalOwner, lease.recoveryTerminal
	lease.mu.Unlock()
	if !terminal || owner == nil || (wantBinding && owner.binding == nil) {
		t.Fatalf("terminal owner missing: terminal=%v owner=%+v", terminal, owner)
	}
}

// coldTerminalForensicRelease is test-only cleanup after the assertions above.
// It intentionally does not call lease.Close again or retry the ambiguous
// production close; it only quiesces a retained real VFS when present and
// releases the test process's root descriptor.
func coldTerminalForensicRelease(t *testing.T, lease *rootLease) {
	t.Helper()
	lease.mu.Lock()
	owner, fd := lease.recoveryTerminalOwner, lease.fd
	lease.mu.Unlock()
	if owner != nil && owner.binding != nil && owner.binding.vfs != nil && !owner.binding.vfs.closed {
		if err := owner.binding.vfs.Close(); err != nil {
			t.Fatalf("forensic VFS cleanup: %v", err)
		}
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatalf("forensic terminal unlock: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("forensic terminal close: %v", err)
	}
}
