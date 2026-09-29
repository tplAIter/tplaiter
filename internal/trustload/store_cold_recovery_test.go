//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStoreColdRecoveryBoundsAndHotRetention(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name   string
		size   int64
		first  byte
		want   error
		absent bool
	}{
		{"cold-zero", 0, 0, nil, true},
		{"cold-one", 1, 0, nil, true},
		{"cold-page", 4096, 0, nil, true},
		{"cold-budget", coldJournalInspectBudget, 0, nil, true},
		{"cold-oversize", coldJournalInspectBudget + 1, 0, ErrPending, false},
		{"hot-oversize-real-sqlite-control", coldJournalInspectBudget + 1, 1, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newColdRecoveryRoot(t, tc.size, tc.first)
			lease, err := openRootLease(context.Background(), root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			err = recoverStoreColdJournal(context.Background(), lease)
			closeErr := lease.Close()
			if tc.want == nil {
				if err != nil || closeErr != nil {
					t.Fatalf("recover=%v close=%v", err, closeErr)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("recover=%v want=%v", err, tc.want)
			}
			_, statErr := os.Stat(filepath.Join(root, storeDBName+"-journal"))
			if tc.absent && !os.IsNotExist(statErr) {
				t.Fatalf("journal retained: %v", statErr)
			}
			if !tc.absent && statErr != nil {
				t.Fatalf("journal unexpectedly absent: %v", statErr)
			}
		})
	}
}

func TestStoreColdRecoveryPostUnlinkFaultObservations(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("sync failure still observes absence", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeSyncDirectory
		storeSyncDirectory = func(int) error { return unix.EIO }
		t.Cleanup(func() { storeSyncDirectory = old })
		lease, _ := openRootLease(context.Background(), root, storeRecover)
		err := recoverStoreColdJournal(context.Background(), lease)
		_ = lease.Close()
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(e) {
			t.Fatalf("sync failure did not leave observed absent: %v", e)
		}
	})
	t.Run("absence observation failure is unsuccessful", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeRecoveryFstatat
		oldUnlink := storeUnlinkat
		calls := 0
		unlinkCalls := 0
		storeRecoveryFstatat = func(fd int, name string, st *unix.Stat_t, flags int) error {
			calls++
			// The helper checks the entry before and after the before-unlink
			// synchronization point. The third journal fstatat is therefore the
			// post-unlink absence observation under test.
			if calls == 3 {
				return unix.EIO
			}
			return old(fd, name, st, flags)
		}
		storeUnlinkat = func(fd int, name string, flags int) error {
			unlinkCalls++
			return oldUnlink(fd, name, flags)
		}
		t.Cleanup(func() { storeRecoveryFstatat, storeUnlinkat = old, oldUnlink })
		lease, _ := openRootLease(context.Background(), root, storeRecover)
		err := recoverStoreColdJournal(context.Background(), lease)
		_ = lease.Close()
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if calls != 3 || unlinkCalls != 1 {
			t.Fatalf("absence observation phases fstatat=%d unlink=%d want fstatat=3 unlink=1", calls, unlinkCalls)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(e) {
			t.Fatalf("journal not physically absent: %v", e)
		}
	})
	t.Run("unlink failure retains journal", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeUnlinkat
		storeUnlinkat = func(int, string, int) error { return unix.EIO }
		t.Cleanup(func() { storeUnlinkat = old })
		lease, _ := openRootLease(context.Background(), root, storeRecover)
		err := recoverStoreColdJournal(context.Background(), lease)
		_ = lease.Close()
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); e != nil {
			t.Fatalf("unlink failure removed journal: %v", e)
		}
	})
	t.Run("post-unlink journal close becomes terminal", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeRecoveryClose
		calls := 0
		storeRecoveryClose = func(fd int) error {
			calls++
			err := unix.Close(fd)
			if calls == 2 && err == nil {
				return unix.EIO
			}
			return err
		}
		t.Cleanup(func() { storeRecoveryClose = old })
		lease, _ := openRootLease(context.Background(), root, storeRecover)
		rootFD := lease.fd
		err := recoverStoreColdJournal(context.Background(), lease)
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if err := lease.Close(); !errors.Is(err, unix.EIO) {
			t.Fatalf("terminal close=%v", err)
		}
		if calls != 2 {
			t.Fatalf("journal close calls=%d want 2", calls)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(e) {
			t.Fatalf("post-unlink close error restored journal: %v", e)
		}
		if err := unix.Flock(rootFD, unix.LOCK_UN); err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(rootFD); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("pre-inspection journal close becomes terminal", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeRecoveryClose
		storeRecoveryClose = func(fd int) error {
			_ = unix.Close(fd)
			return unix.EIO
		}
		t.Cleanup(func() { storeRecoveryClose = old })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("pre-inspection close recovery=%v", err)
		}
		if err := lease.Close(); !errors.Is(err, unix.EIO) {
			t.Fatalf("pre-inspection terminal close=%v", err)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
			t.Fatalf("pre-inspection close removed journal: %v", err)
		}
	})
}

func TestStoreColdRecoveryCancellationAndCloseVeto(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("cancel after recovery before unlink", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeRecoveryHook
		ctx, cancel := context.WithCancel(context.Background())
		storeRecoveryHook = func(stage string) {
			if stage == "after-recovery" {
				cancel()
			}
		}
		t.Cleanup(func() { storeRecoveryHook = old })
		lease, _ := openRootLease(context.Background(), root, storeRecover)
		err := recoverStoreColdJournal(ctx, lease)
		_ = lease.Close()
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); e != nil {
			t.Fatalf("cancelled path removed journal: %v", e)
		}
	})
	t.Run("close request before unlink", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old := storeRecoveryHook
		closeResult := make(chan error, 1)
		entered := make(chan struct{})
		resume := make(chan struct{})
		recoveryResult := make(chan error, 1)
		var lease *rootLease
		storeRecoveryHook = func(stage string) {
			if stage == "before-unlink" {
				close(entered)
				<-resume
			}
		}
		t.Cleanup(func() { storeRecoveryHook = old })
		lease, _ = openRootLease(context.Background(), root, storeRecover)
		go func() { recoveryResult <- recoverStoreColdJournal(context.Background(), lease) }()
		<-entered
		go func() { closeResult <- lease.Close() }()
		waitRecoveryCloseRequest(t, lease)
		close(resume)
		err := <-recoveryResult
		if !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("recover=%v", err)
		}
		if e := <-closeResult; e != nil {
			t.Fatalf("waiting close=%v", e)
		}
		if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); e != nil {
			t.Fatalf("close-veto removed journal: %v", e)
		}
	})
}

func TestStoreColdRecoveryHealthGateBlocksUnlink(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, phase := range []string{"query:0", "integrity"} {
		t.Run(phase, func(t *testing.T) {
			root := newColdRecoveryRoot(t, 0, 0)
			ctx := context.WithValue(context.Background(), storeRecoveryHealthFaultKey{}, storeRecoveryHealthFault{phase: phase, err: unix.EIO})
			lease, err := openRootLease(ctx, root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			err = recoverStoreColdJournal(ctx, lease)
			_ = lease.Close()
			if err == nil {
				t.Fatal("health fault allowed recovery")
			}
			if _, e := os.Stat(filepath.Join(root, storeDBName+"-journal")); e != nil {
				t.Fatalf("health fault removed journal: %v", e)
			}
		})
	}
}

func TestStoreColdRecoveryRecordsEXAtime(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	root := newColdRecoveryRoot(t, 1, 0)
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	evidence, fd, err := lease.inspectColdJournal(true)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if err := closeColdJournalFD(&fd); err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if !evidence.atimeBefore.valid || !evidence.atimeAfterClassify.valid || !evidence.atimeAfterScan.valid {
		t.Fatalf("atime observations missing: %+v", evidence)
	}
}

func TestStoreColdRecoveryOversizePreservesEXAtime(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	root := newColdRecoveryRoot(t, coldJournalInspectBudget+1, 0)
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	evidence, fd, err := lease.inspectColdJournal(false)
	if fd != -1 {
		t.Fatalf("oversize inspection retained fd=%d", fd)
	}
	if !errors.Is(err, ErrPending) {
		_ = lease.Close()
		t.Fatalf("oversize inspection err=%v want pending", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if !evidence.zero || evidence.bytesRead != 1 || evidence.digest != "" {
		t.Fatalf("oversize evidence=%+v", evidence)
	}
	if !evidence.atimeBefore.valid || !evidence.atimeAfterClassify.valid || evidence.atimeAfterScan.valid {
		t.Fatalf("oversize atime observations=%+v", evidence)
	}
}

func TestStoreColdRecoveryCancellationDuringColdScan(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	root := newColdRecoveryRoot(t, 128<<10, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := storeRecoveryHook
	storeRecoveryHook = func(stage string) {
		if stage == "cold-scan" {
			cancel()
		}
	}
	t.Cleanup(func() { storeRecoveryHook = old })
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	err = recoverStoreColdJournal(ctx, lease)
	if !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("cold scan cancellation err=%v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
		t.Fatalf("cancelled cold scan removed journal: %v", err)
	}
}

func TestStoreColdRecoveryCancellationAfterUnlinkCompletesObservations(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	root := newColdRecoveryRoot(t, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	old := storeRecoveryHook
	storeRecoveryHook = func(stage string) {
		if stage == "after-unlink" {
			// The hook is invoked only after sync, absence observation and the
			// owned journal descriptor close have all been attempted.
			cancel()
		}
	}
	t.Cleanup(func() {
		cancel()
		storeRecoveryHook = old
	})
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	err = recoverStoreColdJournal(ctx, lease)
	if !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("post-unlink cancellation err=%v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(err) {
		t.Fatalf("post-unlink cancellation journal state=%v", err)
	}
}

func TestStoreColdRecoveryRealSQLiteHotControl(t *testing.T) {
	if os.Getenv("TPLAITER_COLD_HOT_CHILD") == "1" {
		root := os.Getenv("TPLAITER_COLD_HOT_ROOT")
		ready := os.Getenv("TPLAITER_COLD_HOT_READY")
		lease, err := openRootLease(context.Background(), root, storeEnroll)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
		if err != nil {
			_ = lease.Close()
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), "CREATE TABLE hot_control(v INTEGER); INSERT INTO hot_control VALUES(1)"); err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE; UPDATE hot_control SET v=2"); err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, ready := filepath.Join(base, "store"), filepath.Join(base, "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreColdRecoveryRealSQLiteHotControl$")
	cmd.Env = append(os.Environ(), "TPLAITER_COLD_HOT_CHILD=1", "TPLAITER_COLD_HOT_ROOT="+root, "TPLAITER_COLD_HOT_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SQLite hot child did not reach interrupted transaction")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("hot child unexpectedly exited cleanly")
	}
	journal := filepath.Join(root, storeDBName+"-journal")
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("real SQLite hot journal missing: %v", err)
	}
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverStoreColdJournal(context.Background(), lease); err != nil {
		_ = lease.Close()
		t.Fatalf("real SQLite hot recovery: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("SQLite-owned hot journal retained: %v", err)
	}
	read, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := openSQLBinding(context.Background(), read, storeRead)
	if err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	var got int
	if err := binding.conn.QueryRowContext(context.Background(), "SELECT v FROM hot_control").Scan(&got); err != nil || got != 1 {
		_ = binding.Close()
		_ = read.Close()
		t.Fatalf("hot recovery value=%d err=%v", got, err)
	}
	if err := binding.Close(); err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreColdRecoveryRealSQLiteOversizeHotControl(t *testing.T) {
	if os.Getenv("TPLAITER_COLD_HOT_LARGE_CHILD") == "1" {
		root := os.Getenv("TPLAITER_COLD_HOT_LARGE_ROOT")
		ready := os.Getenv("TPLAITER_COLD_HOT_LARGE_READY")
		stage := os.Getenv("TPLAITER_COLD_HOT_LARGE_STAGE")
		started := time.Now()
		reportStage := func(name string) {
			value := name + " elapsed=" + time.Since(started).Round(time.Millisecond).String()
			if err := os.WriteFile(stage, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		reportStage("lease")
		lease, err := openRootLease(context.Background(), root, storeEnroll)
		if err != nil {
			t.Fatal(err)
		}
		reportStage("binding")
		binding, err := openSQLBinding(context.Background(), lease, storeEnroll)
		if err != nil {
			_ = lease.Close()
			t.Fatal(err)
		}
		if _, err := binding.conn.ExecContext(context.Background(), `CREATE TABLE hot_large(id INTEGER PRIMARY KEY, v BLOB)`); err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		reportStage("create")
		_, err = binding.conn.ExecContext(context.Background(), `WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 70000)
INSERT INTO hot_large SELECT x, zeroblob(4096) FROM seq`)
		if err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		reportStage("seed")
		if _, err := binding.conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		reportStage("begin")
		if _, err := binding.conn.ExecContext(context.Background(), "UPDATE hot_large SET v=zeroblob(4095)||x'01'"); err != nil {
			_ = binding.Close()
			_ = lease.Close()
			t.Fatal(err)
		}
		reportStage("update")
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		reportStage("ready")
		time.Sleep(60 * time.Second)
		return
	}
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, ready, stage := filepath.Join(base, "store-large"), filepath.Join(base, "ready-large"), filepath.Join(base, "stage-large")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreColdRecoveryRealSQLiteOversizeHotControl$")
	cmd.Env = append(os.Environ(), "TPLAITER_COLD_HOT_LARGE_CHILD=1", "TPLAITER_COLD_HOT_LARGE_ROOT="+root, "TPLAITER_COLD_HOT_LARGE_READY="+ready, "TPLAITER_COLD_HOT_LARGE_STAGE="+stage)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	deadline := childReadinessDeadline(t, 120*time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			stageValue, stageErr := os.ReadFile(stage)
			t.Logf("large SQLite hot child reached ready: stage=%q stageErr=%v", stageValue, stageErr)
			break
		}
		if time.Now().After(deadline) {
			stageValue, stageErr := os.ReadFile(stage)
			t.Fatalf("large SQLite hot child did not reach interrupted transaction by %s: stage=%q stageErr=%v", deadline.Format(time.RFC3339Nano), stageValue, stageErr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("large hot child unexpectedly exited cleanly")
	}
	journal := filepath.Join(root, storeDBName+"-journal")
	stat, err := os.Stat(journal)
	if err != nil {
		t.Fatalf("large SQLite hot journal missing: %v", err)
	}
	if stat.Size() <= coldJournalInspectBudget {
		t.Fatalf("large SQLite hot journal size=%d <= inspection budget=%d", stat.Size(), coldJournalInspectBudget)
	}
	lease, err := openRootLease(context.Background(), root, storeRecover)
	if err != nil {
		t.Fatal(err)
	}
	evidence, fd, err := lease.inspectColdJournal(false)
	if err != nil || fd != -1 {
		_ = lease.Close()
		t.Fatalf("large hot classification evidence=%+v fd=%d err=%v", evidence, fd, err)
	}
	if evidence.firstByte == 0 || evidence.bytesRead != 1 || evidence.digest != "" || evidence.zero {
		_ = lease.Close()
		t.Fatalf("large hot classification=%+v; expected one nonzero classification byte and no digest", evidence)
	}
	if err := recoverStoreColdJournal(context.Background(), lease); err != nil {
		_ = lease.Close()
		t.Fatalf("large SQLite hot recovery: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("SQLite-owned large hot journal retained: %v", err)
	}
	read, err := openRootLease(context.Background(), root, storeRead)
	if err != nil {
		t.Fatal(err)
	}
	readBinding, err := openSQLBinding(context.Background(), read, storeRead)
	if err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	var unchanged int
	if err := readBinding.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM hot_large WHERE v=zeroblob(4096)").Scan(&unchanged); err != nil || unchanged != 70000 {
		_ = readBinding.Close()
		_ = read.Close()
		t.Fatalf("large hot rollback unchanged zeroblob count=%d err=%v", unchanged, err)
	}
	var changed int
	if err := readBinding.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM hot_large WHERE v=zeroblob(4095)||x'01'").Scan(&changed); err != nil || changed != 0 {
		_ = readBinding.Close()
		_ = read.Close()
		t.Fatalf("large hot rollback changed trailing-01 count=%d err=%v", changed, err)
	}
	if err := readStoreRecoveryIntegrity(context.Background(), readBinding.conn); err != nil {
		_ = readBinding.Close()
		_ = read.Close()
		t.Fatalf("large hot rollback integrity: %v", err)
	}
	if err := readBinding.Close(); err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreColdRecoveryFinalEntryAndFreshReadFailures(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("replacement-at-before-unlink", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 1, 0)
		journal := filepath.Join(root, storeDBName+"-journal")
		oldHook, oldSync := storeRecoveryHook, storeSyncDirectory
		storeRecoveryHook = func(stage string) {
			if stage == "before-unlink" {
				if err := os.Rename(journal, journal+".old"); err != nil {
					t.Errorf("replace rename: %v", err)
					return
				}
				if err := os.WriteFile(journal, []byte{0}, 0o600); err != nil {
					t.Errorf("replacement write: %v", err)
				}
			}
		}
		syncCalls := 0
		storeSyncDirectory = func(fd int) error { syncCalls++; return oldSync(fd) }
		t.Cleanup(func() { storeRecoveryHook, storeSyncDirectory = oldHook, oldSync })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("replacement recovery=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if syncCalls != 0 {
			t.Fatalf("replacement reached unlink/sync: %d", syncCalls)
		}
		if _, err := os.Stat(journal); err != nil {
			t.Fatalf("replacement removed: %v", err)
		}
	})
	t.Run("post-recovery-digest-mismatch", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 4096, 0)
		journal := filepath.Join(root, storeDBName+"-journal")
		old := storeRecoveryHook
		storeRecoveryHook = func(stage string) {
			if stage == "after-recovery" {
				if err := os.WriteFile(journal, append([]byte{1}, make([]byte, 4095)...), 0o600); err != nil {
					t.Errorf("digest mutation: %v", err)
				}
			}
		}
		t.Cleanup(func() { storeRecoveryHook = old })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("digest mismatch recovery=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(journal); err != nil {
			t.Fatalf("digest mismatch removed journal: %v", err)
		}
	})
	t.Run("post-recovery-identity-mismatch", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 1, 0)
		journal := filepath.Join(root, storeDBName+"-journal")
		old := storeRecoveryHook
		storeRecoveryHook = func(stage string) {
			if stage != "after-recovery" {
				return
			}
			if err := os.Rename(journal, journal+".prior"); err != nil {
				t.Errorf("identity rename: %v", err)
				return
			}
			if err := os.WriteFile(journal, []byte{0}, 0o600); err != nil {
				t.Errorf("identity replacement: %v", err)
			}
		}
		t.Cleanup(func() { storeRecoveryHook = old })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("identity mismatch recovery=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(journal); err != nil {
			t.Fatalf("identity replacement removed journal: %v", err)
		}
	})
	t.Run("fresh-read-health-failure-after-unlink", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		old, oldHook := storeRecoveryFreshHealthFault, storeRecoveryHook
		storeRecoveryFreshHealthFault = unix.EIO
		freshBinding := false
		storeRecoveryHook = func(stage string) {
			if stage == "fresh-read-binding" {
				freshBinding = true
			}
		}
		t.Cleanup(func() { storeRecoveryFreshHealthFault, storeRecoveryHook = old, oldHook })
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, unix.EIO) {
			t.Fatalf("fresh health failure=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if !freshBinding {
			t.Fatal("fresh health fault did not open the final readonly binding")
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); !os.IsNotExist(err) {
			t.Fatalf("fresh health failure journal=%v", err)
		}
	})
}

func TestStoreColdRecoveryInspectionFaultConsequences(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name    string
		install func(*testing.T, string)
	}{
		{"post-open-error-closes-returned-fd", func(t *testing.T, _ string) {
			old := storeRecoveryOpenat
			storeRecoveryOpenat = func(fd int, name string, flags int, perm uint32) (int, error) {
				got, err := old(fd, name, flags, perm)
				if err != nil {
					return got, err
				}
				return got, unix.EIO
			}
			t.Cleanup(func() { storeRecoveryOpenat = old })
		}},
		{"first-byte-read-error", func(t *testing.T, _ string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 1 && err == nil {
					return n, unix.EIO
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
		{"first-byte-short-read", func(t *testing.T, _ string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 1 && err == nil {
					return 0, nil
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
		{"metadata-change-after-first-byte", func(t *testing.T, journal string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 1 && err == nil {
					if e := os.Chmod(journal, 0o644); e != nil {
						t.Errorf("chmod: %v", e)
					}
				}
				return n, err
			}
			t.Cleanup(func() { _ = os.Chmod(journal, 0o600); storeRecoveryPread = old })
		}},
		{"size-grow-after-first-byte", func(t *testing.T, journal string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 1 && err == nil {
					if e := os.Truncate(journal, 8192); e != nil {
						t.Errorf("grow: %v", e)
					}
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
		{"complete-scan-read-error", func(t *testing.T, _ string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 2 && err == nil {
					return n, unix.EIO
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
		{"complete-scan-short-read", func(t *testing.T, _ string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 2 && err == nil {
					return 0, nil
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
		{"size-truncate-during-complete-scan", func(t *testing.T, journal string) {
			old := storeRecoveryPread
			calls := 0
			storeRecoveryPread = func(fd int, b []byte, off int64) (int, error) {
				calls++
				n, err := old(fd, b, off)
				if calls == 2 && err == nil {
					if e := os.Truncate(journal, 2048); e != nil {
						t.Errorf("truncate: %v", e)
					}
				}
				return n, err
			}
			t.Cleanup(func() { storeRecoveryPread = old })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newColdRecoveryRoot(t, 4096, 0)
			journal := filepath.Join(root, storeDBName+"-journal")
			sentinel := filepath.Join(root, "outside-sentinel")
			if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.install(t, journal)
			lease, err := openRootLease(context.Background(), root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("fault recovery=%v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(journal); err != nil {
				t.Fatalf("fault removed journal: %v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
				t.Fatalf("sentinel changed %q err=%v", data, err)
			}
		})
	}
}

// TestStoreColdRecoveryUnsafeHelperConsequences keeps the unsafe-leaf rows at
// the helper boundary: inspect-only rejection is insufficient evidence that
// recovery cannot unlink, sync, or otherwise mutate the sidecar namespace.
func TestStoreColdRecoveryUnsafeHelperConsequences(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{"symlink", func(t *testing.T, journal, sentinel string) {
			if err := os.Remove(journal); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(sentinel, journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"permissive-mode", func(t *testing.T, journal, _ string) {
			if err := os.Chmod(journal, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"WAL-present", func(t *testing.T, journal, _ string) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(journal), storeDBName+"-wal"), []byte("wal"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newColdRecoveryRoot(t, 1, 0)
			journal := filepath.Join(root, storeDBName+"-journal")
			sentinel := filepath.Join(root, "outside-sentinel")
			if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, journal, sentinel)
			lease, err := openRootLease(context.Background(), root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			got := recoverStoreColdJournal(context.Background(), lease)
			if tc.name == "WAL-present" {
				if !errors.Is(got, ErrPending) {
					t.Fatalf("WAL helper=%v", got)
				}
			} else if !errors.Is(got, ErrProvenanceUnavailable) {
				t.Fatalf("unsafe helper=%v", got)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
				t.Fatalf("sentinel changed data=%q err=%v", data, err)
			}
			if tc.name == "symlink" {
				if st, err := os.Lstat(journal); err != nil || st.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("symlink changed stat=%v err=%v", st, err)
				}
			} else if _, err := os.Stat(journal); err != nil {
				t.Fatalf("journal removed: %v", err)
			}
		})
	}
}

func TestStoreColdRecoverySHMFIFOAndOwnerPredicate(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	t.Run("SHM-pending-and-ordinary-read-nonmutating", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 1, 0)
		shm := filepath.Join(root, storeDBName+"-shm")
		if err := os.WriteFile(shm, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrPending) {
			t.Fatalf("SHM recovery=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(shm); err != nil || string(data) != "sentinel" {
			t.Fatalf("SHM changed data=%q err=%v", data, err)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
			t.Fatalf("SHM removed journal: %v", err)
		}
		read, err := openRootLease(context.Background(), root, storeRead)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openSQLBinding(context.Background(), read, storeRead); !errors.Is(err, ErrPending) {
			_ = read.Close()
			t.Fatalf("ordinary SHM read=%v", err)
		}
		if err := read.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("native-FIFO-nonblocking", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		journal := filepath.Join(root, storeDBName+"-journal")
		if err := os.Remove(journal); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(journal, 0o600); err != nil {
			t.Fatal(err)
		}
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- recoverStoreColdJournal(context.Background(), lease) }()
		select {
		case err := <-result:
			if !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("FIFO recovery=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("FIFO inspection blocked")
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if st, err := os.Lstat(journal); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("FIFO changed stat=%v err=%v", st, err)
		}
	})
	t.Run("owner-predicate-injection", func(t *testing.T) {
		root := newColdRecoveryRoot(t, 0, 0)
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		lease.uidOverride = uint32(unix.Geteuid()) + 1
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("owner predicate recovery=%v", err)
		}
		lease.uidOverride = 0
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
			t.Fatalf("owner predicate removed journal: %v", err)
		}
	})
	t.Run("native-wrong-owner-unavailable-without-privilege", func(t *testing.T) {
		if unix.Geteuid() != 0 {
			t.Skip("native wrong-owner fixture requires chown privilege; predicate row above is not credited as native ownership")
		}
		root := newColdRecoveryRoot(t, 0, 0)
		journal := filepath.Join(root, storeDBName+"-journal")
		if err := os.Chown(journal, 1, -1); err != nil {
			t.Skipf("native wrong-owner fixture unavailable: %v", err)
		}
		defer func() { _ = os.Chown(journal, int(unix.Geteuid()), -1) }()
		lease, err := openRootLease(context.Background(), root, storeRecover)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("native wrong-owner recovery=%v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(journal); err != nil {
			t.Fatalf("native wrong-owner removed journal: %v", err)
		}
	})
}

func TestStoreColdRecoveryCloseDuringEachColdScan(t *testing.T) {
	if !storePlatformAvailable() {
		t.Skip("unsupported platform")
	}
	for _, tc := range []struct {
		name    string
		trigger int
	}{{"pre-scan", 1}, {"post-scan", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			root := newColdRecoveryRoot(t, 128<<10, 0)
			lease, err := openRootLease(context.Background(), root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			rootFD := lease.fd
			old := storeRecoveryHook
			calls := 0
			closeResult := make(chan error, 1)
			storeRecoveryHook = func(stage string) {
				if stage != "cold-scan" {
					return
				}
				calls++
				if calls != tc.trigger {
					return
				}
				go func() { closeResult <- lease.Close() }()
				waitRecoveryCloseRequest(t, lease)
				if _, err := unix.FcntlInt(uintptr(rootFD), unix.F_GETFD, 0); err != nil {
					t.Errorf("root FD released during %s: %v", tc.name, err)
				}
			}
			t.Cleanup(func() { storeRecoveryHook = old })
			if err := recoverStoreColdJournal(context.Background(), lease); !errors.Is(err, ErrProvenanceUnavailable) {
				t.Fatalf("Close during %s recovery=%v", tc.name, err)
			}
			select {
			case err := <-closeResult:
				if err != nil {
					t.Fatalf("Close during %s=%v", tc.name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Close during %s did not finish", tc.name)
			}
			if _, err := os.Stat(filepath.Join(root, storeDBName+"-journal")); err != nil {
				t.Fatalf("Close during %s removed journal: %v", tc.name, err)
			}
		})
	}
}

func TestStoreColdRecoveryUnsafeDirectoryAndHardlinkConsequences(t *testing.T) {
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
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		make func(string) error
		keep string
	}{
		{"directory", func(path string) error { return os.Mkdir(path, 0o700) }, ""},
		{"hardlink", func(path string) error {
			source := filepath.Join(base, "hardlink-source")
			if err := os.WriteFile(source, []byte{0}, 0o600); err != nil {
				return err
			}
			return os.Link(source, path)
		}, filepath.Join(base, "hardlink-source")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := filepath.Join(root, storeDBName+"-journal")
			if err := tc.make(journal); err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(journal)
			defer func() {
				if tc.keep != "" {
					_ = os.Remove(tc.keep)
				}
			}()
			lease, err := openRootLease(context.Background(), root, storeRecover)
			if err != nil {
				t.Fatal(err)
			}
			got := recoverStoreColdJournal(context.Background(), lease)
			closeErr := lease.Close()
			if !errors.Is(got, ErrProvenanceUnavailable) || closeErr != nil {
				t.Fatalf("helper=%v close=%v want provenance failure and clean close", got, closeErr)
			}
			if _, err := os.Lstat(journal); err != nil {
				t.Fatalf("unsafe sidecar removed: %v", err)
			}
		})
	}
}

func newColdRecoveryRoot(t *testing.T, size int64, first byte) string {
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
	b, err := openSQLBinding(context.Background(), lease, storeEnroll)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if _, err = b.conn.ExecContext(context.Background(), "CREATE TABLE cold_matrix(v INTEGER); INSERT INTO cold_matrix VALUES(1)"); err != nil {
		_ = b.Close()
		_ = lease.Close()
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(root, storeDBName+"-journal"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if size > 0 && first != 0 {
		if _, err = f.WriteAt([]byte{first}, 0); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}

// childReadinessDeadline returns how long to wait for a helper child to reach
// its interrupted state. It never waits less than floor, and under a longer
// go test -timeout it extends to the test binary's own deadline (minus a
// margin to report the failure), so a slow -race run on a loaded host does not
// fail on a fixed wall-clock budget.
func childReadinessDeadline(t *testing.T, floor time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(floor)
	if testDeadline, ok := t.Deadline(); ok {
		if extended := testDeadline.Add(-30 * time.Second); extended.After(deadline) {
			deadline = extended
		}
	}
	return deadline
}
