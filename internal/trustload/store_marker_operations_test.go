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

	"golang.org/x/sys/unix"
)

// These are deliberately low-level tests. They exercise only rootLease's
// descriptor-relative marker protocol; Store.Load/Verify integration belongs
// to the store integration matrix.
func TestMarkerOperationRoundTripAndPrivatePredicates(t *testing.T) {
	lease, root := newMarkerEnrollLease(t)
	defer func() { _ = lease.Close() }()
	raw := []byte("marker bytes are compared exactly")
	if err := lease.writePendingMarker(context.Background(), raw); err != nil {
		t.Fatalf("write pending: %v", err)
	}
	pending := filepath.Join(root, pendingMarkerName)
	var st unix.Stat_t
	if err := unix.Lstat(pending, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(unix.Geteuid()) || st.Mode&0o077 != 0 {
		t.Fatalf("pending predicates: mode=%#o nlink=%d uid=%d", st.Mode, st.Nlink, st.Uid)
	}
	got, err := lease.readMarker(context.Background(), pendingMarkerName, len(raw))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("read pending = %q, %v", got, err)
	}
	if _, err := lease.readMarker(context.Background(), pendingMarkerName, len(raw)-1); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("bounded read = %v", err)
	}
	if err := lease.activatePendingMarker(context.Background(), raw); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending after activation = %v", err)
	}
	got, err = lease.readMarker(context.Background(), activeMarkerName, len(raw))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("read active = %q, %v", got, err)
	}
}

func TestMarkerReadRejectsHostileEntriesWithoutBlocking(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{"symlink", func(t *testing.T, root string) {
			outside := filepath.Join(filepath.Dir(root), "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, activeMarkerName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, root string) {
			if err := unix.Mkfifo(filepath.Join(root, activeMarkerName), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"group-readable", func(t *testing.T, root string) {
			writeMarkerFixture(t, filepath.Join(root, activeMarkerName), []byte("x"), 0o640)
		}},
		{"hard-link", func(t *testing.T, root string) {
			marker := filepath.Join(root, activeMarkerName)
			writeMarkerFixture(t, marker, []byte("x"), 0o600)
			if err := os.Link(marker, filepath.Join(root, "linked")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, root := newMarkerEnrollLease(t)
			defer func() { _ = lease.Close() }()
			tc.setup(t, root)
			result := make(chan error, 1)
			go func() { _, err := lease.readMarker(context.Background(), activeMarkerName, 64); result <- err }()
			select {
			case err := <-result:
				if !errors.Is(err, ErrProvenanceUnavailable) {
					t.Fatalf("hostile read = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("hostile marker read blocked")
			}
		})
	}
}

func TestMarkerReadRejectsOwnerPredicate(t *testing.T) {
	lease, root := newMarkerEnrollLease(t)
	defer func() { _ = lease.Close() }()
	writeMarkerFixture(t, filepath.Join(root, activeMarkerName), []byte("x"), 0o600)
	// A test cannot safely chown on every native runner. uidOverride is the
	// existing private predicate hook, so this row proves that owner identity
	// participates in acceptance without claiming a native wrong-owner fixture.
	lease.uidOverride = uint32(unix.Geteuid()) + 1
	if _, err := lease.readMarker(context.Background(), activeMarkerName, 64); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("wrong owner predicate accepted marker: %v", err)
	}
}

func TestMarkerWriteAndActivationRemainExclusive(t *testing.T) {
	lease, root := newMarkerEnrollLease(t)
	defer func() { _ = lease.Close() }()
	raw := []byte("pending")
	if err := lease.writePendingMarker(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if err := lease.writePendingMarker(context.Background(), raw); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("second pending write = %v", err)
	}
	if err := lease.activatePendingMarker(context.Background(), []byte("other")); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("mismatched activation = %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, pendingMarkerName)); err != nil || !bytes.Equal(b, raw) {
		t.Fatalf("mismatch altered pending: %q, %v", b, err)
	}
	writeMarkerFixture(t, filepath.Join(root, activeMarkerName), []byte("existing"), 0o600)
	if err := lease.activatePendingMarker(context.Background(), raw); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("activation overwrite = %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, activeMarkerName)); err != nil || string(b) != "existing" {
		t.Fatalf("active was overwritten: %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(root, pendingMarkerName)); err != nil || !bytes.Equal(b, raw) {
		t.Fatalf("rename failure lost pending: %q, %v", b, err)
	}
}

func TestMarkerOperationsRejectCancellationAndReplacedRoot(t *testing.T) {
	lease, root := newMarkerEnrollLease(t)
	defer func() { _ = lease.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lease.readMarker(ctx, activeMarkerName, 64); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("cancelled read = %v", err)
	}
	if err := lease.writePendingMarker(ctx, []byte("pending")); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("cancelled pending write = %v", err)
	}
	if err := lease.activatePendingMarker(ctx, []byte("pending")); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("cancelled activation = %v", err)
	}
	writeMarkerFixture(t, filepath.Join(root, activeMarkerName), []byte("active"), 0o600)
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.readMarker(context.Background(), activeMarkerName, 64); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("replaced root accepted marker: %v", err)
	}
}

func TestMarkerReadFaultMatrixUsesRealReadAttempts(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(t *testing.T)
	}{
		{"short", func(t *testing.T) {
			old := storeMarkerPread
			calls := 0
			storeMarkerPread = func(fd int, p []byte, off int64) (int, error) {
				calls++
				if calls == 1 {
					return old(fd, p[:len(p)/2], off)
				}
				return old(fd, p, off)
			}
			t.Cleanup(func() {
				if calls < 2 {
					t.Errorf("short read did not retry: calls=%d", calls)
				}
			})
		}},
		{"eintr-no-progress", func(t *testing.T) {
			old := storeMarkerPread
			calls := 0
			storeMarkerPread = func(fd int, p []byte, off int64) (int, error) {
				calls++
				if calls == 1 {
					_, _ = old(fd, p[:0], off)
					return 0, unix.EINTR
				}
				return old(fd, p, off)
			}
			t.Cleanup(func() {
				if calls < 2 {
					t.Errorf("EINTR read did not retry: calls=%d", calls)
				}
			})
		}},
		{"post-read-error", func(t *testing.T) {
			old := storeMarkerPread
			storeMarkerPread = func(fd int, p []byte, off int64) (int, error) {
				n, _ := old(fd, p, off)
				return n, unix.EIO // actual bytes may have been observed; failure is authoritative.
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, root := newMarkerEnrollLease(t)
			defer func() { _ = lease.Close() }()
			writeMarkerFixture(t, filepath.Join(root, activeMarkerName), []byte("read matrix"), 0o600)
			restoreMarkerSeams(t)
			tc.wrap(t)
			got, err := lease.readMarker(context.Background(), activeMarkerName, 64)
			if tc.name == "post-read-error" {
				if !errors.Is(err, ErrProvenanceUnavailable) || got != nil {
					t.Fatalf("post-read error = %q, %v", got, err)
				}
				return
			}
			if err != nil || string(got) != "read matrix" {
				t.Fatalf("read=%q err=%v", got, err)
			}
		})
	}
}

func TestMarkerWriteFaultMatrixPreservesExclusiveArtifact(t *testing.T) {
	for _, tc := range []struct {
		name        string
		wrap        func(t *testing.T)
		wantSuccess bool
	}{
		{"partial-real-prefix", func(t *testing.T) {
			old := storeMarkerWrite
			calls := 0
			storeMarkerWrite = func(fd int, p []byte) (int, error) {
				calls++
				if calls == 1 {
					return old(fd, p[:len(p)/2])
				}
				return old(fd, p)
			}
			t.Cleanup(func() {
				if calls < 2 {
					t.Errorf("partial write did not retry: calls=%d", calls)
				}
			})
		}, true},
		{"eintr-no-progress", func(t *testing.T) {
			old := storeMarkerWrite
			calls := 0
			storeMarkerWrite = func(fd int, p []byte) (int, error) {
				calls++
				if calls == 1 {
					_, _ = old(fd, p[:0])
					return 0, unix.EINTR
				}
				return old(fd, p)
			}
			t.Cleanup(func() {
				if calls < 2 {
					t.Errorf("EINTR write did not retry: calls=%d", calls)
				}
			})
		}, true},
		{"post-write-error-unknown-outcome", func(t *testing.T) {
			old := storeMarkerWrite
			storeMarkerWrite = func(fd int, p []byte) (int, error) { n, _ := old(fd, p); return n, unix.EIO }
		}, false},
		{"file-sync", func(t *testing.T) {
			old := storeMarkerSyncFile
			storeMarkerSyncFile = func(fd int) error { _ = old(fd); return unix.EIO }
		}, false},
		{"close", func(t *testing.T) {
			old := storeMarkerClose
			storeMarkerClose = func(fd int) error { _ = old(fd); return unix.EIO }
		}, false},
		{"directory-sync", func(t *testing.T) {
			old := storeMarkerSyncDirectory
			storeMarkerSyncDirectory = func(fd int) error { _ = old(fd); return unix.EIO }
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, root := newMarkerEnrollLease(t)
			defer func() { _ = lease.Close() }()
			restoreMarkerSeams(t)
			tc.wrap(t)
			raw := []byte("write matrix")
			err := lease.writePendingMarker(context.Background(), raw)
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("write = %v", err)
				}
				if got, e := os.ReadFile(filepath.Join(root, pendingMarkerName)); e != nil || !bytes.Equal(got, raw) {
					t.Fatalf("pending=%q err=%v", got, e)
				}
				return
			}
			if !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("fault write = %v", err)
			}
			if _, e := os.Lstat(filepath.Join(root, pendingMarkerName)); e != nil {
				t.Fatalf("fault removed exclusive pending artifact: %v", e)
			}
		})
	}
}

func TestMarkerActivationFaultMatrixObservesMutatedNamespace(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(t *testing.T, cancel context.CancelFunc)
	}{
		{"rename-post-error-unknown-outcome", func(t *testing.T, _ context.CancelFunc) {
			old := storeMarkerRenameNoReplace
			oldSync, oldStat := storeMarkerSyncDirectory, storeMarkerFstatat
			syncCalls, statCalls := 0, 0
			storeMarkerSyncDirectory = func(fd int) error { syncCalls++; return oldSync(fd) }
			storeMarkerFstatat = func(fd int, name string, st *unix.Stat_t, flags int) error {
				statCalls++
				return oldStat(fd, name, st, flags)
			}
			storeMarkerRenameNoReplace = func(rootFD int, pending, active string) error { _ = old(rootFD, pending, active); return unix.EIO }
			t.Cleanup(func() {
				if syncCalls != 1 {
					t.Errorf("uncertain rename directory sync calls=%d want 1", syncCalls)
				}
				if statCalls < 6 {
					t.Errorf("uncertain rename descriptor-relative fstatat calls=%d want >=6", statCalls)
				}
			})
		}},
		{"directory-sync-post-rename", func(t *testing.T, _ context.CancelFunc) {
			old := storeMarkerSyncDirectory
			storeMarkerSyncDirectory = func(fd int) error { _ = old(fd); return unix.EIO }
		}},
		{"post-rename-cancellation", func(t *testing.T, cancel context.CancelFunc) {
			oldSync, oldStat := storeMarkerSyncDirectory, storeMarkerFstatat
			syncCalls, statCalls := 0, 0
			storeMarkerSyncDirectory = func(fd int) error { syncCalls++; return oldSync(fd) }
			storeMarkerFstatat = func(fd int, name string, st *unix.Stat_t, flags int) error {
				statCalls++
				return oldStat(fd, name, st, flags)
			}
			storeMarkerOperationHook = func(stage string) {
				if stage == "activation-post-rename-pre-sync" {
					cancel()
				}
			}
			t.Cleanup(func() {
				if syncCalls != 1 {
					t.Errorf("post-rename cancellation directory sync calls=%d want 1", syncCalls)
				}
				if statCalls < 6 {
					t.Errorf("post-rename cancellation descriptor-relative fstatat calls=%d want >=6", statCalls)
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, root := newMarkerEnrollLease(t)
			defer func() { _ = lease.Close() }()
			raw := []byte("activate matrix")
			if err := lease.writePendingMarker(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			restoreMarkerSeams(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.wrap(t, cancel)
			if err := lease.activatePendingMarker(ctx, raw); !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("activation = %v", err)
			}
			if got, e := os.ReadFile(filepath.Join(root, activeMarkerName)); e != nil || !bytes.Equal(got, raw) {
				t.Fatalf("active post-fault=%q err=%v", got, e)
			}
			if _, e := os.Lstat(filepath.Join(root, pendingMarkerName)); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("pending remained after actual rename: %v", e)
			}
		})
	}
}

func TestMarkerReadEntryIdentityAndOperationCaptureHooks(t *testing.T) {
	t.Run("entry-swap", func(t *testing.T) {
		lease, root := newMarkerEnrollLease(t)
		defer func() { _ = lease.Close() }()
		marker := filepath.Join(root, activeMarkerName)
		writeMarkerFixture(t, marker, []byte("first"), 0o600)
		restoreMarkerSeams(t)
		storeMarkerOperationHook = func(stage string) {
			if stage == "read-before-entry-check" {
				if err := os.Rename(marker, marker+"-old"); err != nil {
					t.Errorf("swap old: %v", err)
					return
				}
				writeMarkerFixture(t, marker, []byte("second"), 0o600)
			}
		}
		if _, err := lease.readMarker(context.Background(), activeMarkerName, 64); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("swapped entry accepted: %v", err)
		}
	})
	t.Run("entry-swap-after-payload", func(t *testing.T) {
		lease, root := newMarkerEnrollLease(t)
		defer func() { _ = lease.Close() }()
		marker := filepath.Join(root, activeMarkerName)
		writeMarkerFixture(t, marker, []byte("first"), 0o600)
		restoreMarkerSeams(t)
		storeMarkerOperationHook = func(stage string) {
			if stage != "read-after-payload-before-final-identity" {
				return
			}
			if err := os.Rename(marker, marker+"-payload-old"); err != nil {
				t.Errorf("swap old: %v", err)
				return
			}
			writeMarkerFixture(t, marker, []byte("second"), 0o600)
		}
		if _, err := lease.readMarker(context.Background(), activeMarkerName, 64); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("post-payload swapped entry accepted: %v", err)
		}
	})
	t.Run("close-during-capture", func(t *testing.T) {
		lease, _, _ := newRecoveryLeaseForTest(t)
		rootFD := lease.fd
		restoreMarkerSeams(t)
		entered, release := make(chan struct{}), make(chan struct{})
		storeMarkerOperationHook = func(stage string) {
			if stage == "started-before-capability" {
				close(entered)
				<-release
			}
		}
		started := make(chan error, 1)
		go func() { _, err := lease.beginStoreRootOperation(context.Background(), storeRecover); started <- err }()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- lease.Close() }()
		waitMarkerCloseRequest(t, lease)
		if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
			t.Fatalf("root fd closed during capture: %v", err)
		}
		close(release)
		if err := <-started; !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("begin after Close request=%v", err)
		}
		if err := <-closed; err != nil {
			t.Fatalf("Close=%v", err)
		}
		assertRecoveryFDEBADF(t, rootFD)
	})
}

func TestRootOperationCloseWaitsAndRecoveryIsMutuallyExclusive(t *testing.T) {
	lease, root, _ := newRecoveryLeaseForTest(t)
	rootFD := lease.fd
	op, err := lease.beginStoreRootOperation(context.Background(), storeRecover)
	if err != nil {
		t.Fatalf("begin marker operation: %v", err)
	}
	if _, err := lease.beginStoreRecoveryBorrow(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("recovery overlapped marker operation: %v", err)
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- lease.Close() }()
	waitMarkerCloseRequest(t, lease)
	if err := op.check(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("operation checkpoint after Close = %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
		t.Fatalf("Close released root FD before operation finished: %v", err)
	}
	op.abort()
	if err := <-closeResult; err != nil {
		t.Fatalf("Close = %v", err)
	}
	assertRecoveryFDEBADF(t, rootFD)
	// Reusing the same numeric descriptor cannot revive the operation's
	// captured capability.
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := op.check(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("completed operation accepted reused root FD: %v", err)
	}
}

func TestRootOperationModesAndTerminalOwnerRejectAmbiguousFD(t *testing.T) {
	lease, _ := newMarkerEnrollLease(t)
	defer func() { _ = lease.Close() }()
	if _, err := lease.beginStoreRootOperation(context.Background(), storeRead); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("wrong operation mode = %v", err)
	}
	if owner, err := newStoreRecoveryTerminalOwner(nil, 3, true, unix.EIO); owner != nil || !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("attempted-close FD accepted terminal owner: owner=%+v err=%v", owner, err)
	}
}

func TestRootOperationCompletedCapabilityRejectsActualNumericFDReuse(t *testing.T) {
	if os.Getenv("TPLAITER_MARKER_FD_REUSE_CHILD") == "1" {
		markerFDReuseChild(t)
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootOperationCompletedCapabilityRejectsActualNumericFDReuse$")
	cmd.Env = append(os.Environ(), "TPLAITER_MARKER_FD_REUSE_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated numeric-fd-reuse child: %v: %s", err, out)
	}
}

func TestMarkerCloseUncertaintyRetainsTerminalRootAndExclusiveLock(t *testing.T) {
	if os.Getenv("TPLAITER_MARKER_CLOSE_TERMINAL_CHILD") == "1" {
		markerCloseTerminalChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMarkerCloseUncertaintyRetainsTerminalRootAndExclusiveLock$")
	cmd.Env = append(os.Environ(), "TPLAITER_MARKER_CLOSE_TERMINAL_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated marker close-terminal child: %v: %s", err, out)
	}
}

func markerCloseTerminalChild(t *testing.T) {
	lease, root := newMarkerEnrollLease(t)
	rootFD := lease.fd
	restoreMarkerSeams(t)
	closeCalls := 0
	storeMarkerClose = func(int) error { closeCalls++; return unix.EIO } // failure before any native close: FD disposition is ambiguous.
	if err := lease.writePendingMarker(context.Background(), []byte("terminal pending")); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("uncertain marker close write=%v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("marker close attempts=%d want 1", closeCalls)
	}
	runtime.GC()
	if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
		t.Fatalf("terminal root fd lost after GC: %v", err)
	}
	for _, mode := range []storeMode{storeRead, storeRefresh} {
		contender, err := openRootLease(context.Background(), root, mode)
		if contender != nil {
			_ = contender.Close()
			t.Fatalf("terminal root allowed contender mode=%d", mode)
		}
		if mode == storeRead && !errors.Is(err, ErrPending) {
			t.Fatalf("terminal SH contender=%v", err)
		}
		if mode == storeRefresh && !errors.Is(err, ErrRefreshConflict) {
			t.Fatalf("terminal EX contender=%v", err)
		}
	}
	for attempt := 0; attempt != 2; attempt++ {
		if err := lease.Close(); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("terminal Close[%d]=%v", attempt, err)
		}
		if closeCalls != 1 {
			t.Fatalf("terminal Close[%d] retried marker close: calls=%d", attempt, closeCalls)
		}
		if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
			t.Fatalf("terminal Close[%d] released/reused root fd: %v", attempt, err)
		}
	}
}

func markerFDReuseChild(t *testing.T) {
	lease, root, _ := newRecoveryLeaseForTest(t)
	oldFD := lease.fd
	op, err := lease.beginStoreRootOperation(context.Background(), storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	op.abort()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	assertRecoveryFDEBADF(t, oldFD)
	var held []*os.File
	var reused *os.File
	for range 32 {
		f, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, f)
		if int(f.Fd()) == oldFD {
			reused = f
			break
		}
	}
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()
	if reused == nil {
		t.Fatalf("did not naturally reuse closed root fd=%d; opened=%d", oldFD, len(held))
	}
	if err := op.check(context.Background()); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("completed operation revived by fd %d: %v", oldFD, err)
	}
}

func newMarkerEnrollLease(t *testing.T) (*rootLease, string) {
	t.Helper()
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
	return lease, root
}

func writeMarkerFixture(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func waitMarkerCloseRequest(t *testing.T, lease *rootLease) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lease.mu.Lock()
		requested := lease.operationCloseRequested
		lease.mu.Unlock()
		if requested {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Close did not record marker-operation close request")
}

func restoreMarkerSeams(t *testing.T) {
	t.Helper()
	openat, pread, write := storeMarkerOpenat, storeMarkerPread, storeMarkerWrite
	fstat, fstatat, closeFn := storeMarkerFstat, storeMarkerFstatat, storeMarkerClose
	syncFile, syncDir, renameFn := storeMarkerSyncFile, storeMarkerSyncDirectory, storeMarkerRenameNoReplace
	hook := storeMarkerOperationHook
	t.Cleanup(func() {
		storeMarkerOpenat, storeMarkerPread, storeMarkerWrite = openat, pread, write
		storeMarkerFstat, storeMarkerFstatat, storeMarkerClose = fstat, fstatat, closeFn
		storeMarkerSyncFile, storeMarkerSyncDirectory, storeMarkerRenameNoReplace = syncFile, syncDir, renameFn
		storeMarkerOperationHook = hook
	})
}
