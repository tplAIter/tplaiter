package execx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperEnv selects a helper mode of this test binary (see TestMain).
const helperEnv = "TPLAITER_TEST_HELPER"

// TestMain turns the test binary into a small fixture process when
// TPLAITER_TEST_HELPER is set, so process-group behaviour is tested with a
// real child and a real grandchild without shell-specific quirks.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "spawn-grandchild":
		os.Exit(spawnGrandchildHelper())
	case "ignore-term":
		ignoreTermHelper()
	default:
		os.Exit(97)
	}
}

// spawnGrandchildHelper starts `sh -c 'sleep 300'` (which inherits this
// process group), records "<own pid> <grandchild pid>" in
// $TPLAITER_TEST_PIDFILE and blocks until it is signalled.
func spawnGrandchildHelper() int {
	grandchild := exec.Command("/bin/sh", "-c", "sleep 300")
	if err := grandchild.Start(); err != nil {
		return 98
	}
	pidFile := os.Getenv("TPLAITER_TEST_PIDFILE")
	tmp := pidFile + ".tmp"
	payload := strconv.Itoa(os.Getpid()) + " " + strconv.Itoa(grandchild.Process.Pid)
	if err := os.WriteFile(tmp, []byte(payload), 0o600); err != nil {
		return 99
	}
	if err := os.Rename(tmp, pidFile); err != nil {
		return 99
	}
	_ = grandchild.Wait()
	return 0
}

// ignoreTermHelper ignores SIGTERM, signals readiness, and sleeps, so only
// SIGKILL can stop it.
func ignoreTermHelper() {
	signal.Ignore(syscall.SIGTERM)
	if ready := os.Getenv("TPLAITER_TEST_READY"); ready != "" {
		_ = os.WriteFile(ready, []byte("ready"), 0o600)
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}

func helperCommand(t *testing.T, mode string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{helperEnv + "=" + mode}, env...)...)
	return cmd
}

func waitForFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(testWait(t))
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not written", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readPidPair waits for the helper's "<leader pid> <grandchild pid>" file.
// The leader pid comes from the helper itself, so the test never reads
// cmd.Process while RunGroup is starting it in another goroutine.
func readPidPair(t *testing.T, path string) (leader, grandchild int) {
	t.Helper()
	fields := strings.Fields(string(waitForFile(t, path)))
	if len(fields) != 2 {
		t.Fatalf("malformed pid file %q", fields)
	}
	leader, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err = strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	return leader, grandchild
}

// waitGone polls until kill(target, 0) reports ESRCH. A killed orphan can
// stay a zombie until init reaps it, which kill(2) still reports as present.
func waitGone(t *testing.T, target int, what string) {
	t.Helper()
	deadline := time.Now().Add(testWait(t))
	for {
		err := syscall.Kill(target, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (%d) still exists after cancellation: kill(0)=%v", what, target, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testWait bounds polling by the test deadline, capped to keep failures fast.
func testWait(t *testing.T) time.Duration {
	wait := 30 * time.Second
	if deadline, ok := t.Deadline(); ok {
		if left := time.Until(deadline) / 2; left < wait {
			wait = left
		}
	}
	return wait
}

func TestRunGroupCancelKillsGrandchildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	cmd := helperCommand(t, "spawn-grandchild", "TPLAITER_TEST_PIDFILE="+pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		res GroupResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := RunGroup(ctx, cmd, GroupOptions{Grace: 5 * time.Second})
		done <- outcome{res, err}
	}()
	pgid, grandchild := readPidPair(t, pidFile)
	if got, err := syscall.Getpgid(grandchild); err != nil || got != pgid {
		t.Fatalf("grandchild pgid=%d err=%v, want leader pgid %d", got, err, pgid)
	}
	cancel()
	got := <-done
	if got.res.Stopped != StopContext {
		t.Fatalf("stop reason=%v, want StopContext", got.res.Stopped)
	}
	// The leader may win the race and exit 0 once its children died; the
	// stop reason, not the wait status, is the cancellation evidence.
	waitGone(t, -pgid, "process group")
	waitGone(t, grandchild, "grandchild")
}

func TestRunGroupEscalatesToSIGKILLAfterGrace(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := helperCommand(t, "ignore-term", "TPLAITER_TEST_READY="+ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const grace = 300 * time.Millisecond
	type outcome struct {
		res GroupResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := RunGroup(ctx, cmd, GroupOptions{Grace: grace})
		done <- outcome{res, err}
	}()
	waitForFile(t, ready)
	stoppedAt := time.Now()
	cancel()
	got := <-done
	if !got.res.Killed {
		t.Fatal("a SIGTERM-ignoring group was not escalated to SIGKILL")
	}
	if elapsed := time.Since(stoppedAt); elapsed < grace {
		t.Fatalf("SIGKILL after %v, before the %v grace period", elapsed, grace)
	}
	var exitErr *exec.ExitError
	if !errors.As(got.err, &exitErr) {
		t.Fatalf("wait error=%v, want a signalled exit", got.err)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("leader status=%v, want killed by SIGKILL", exitErr.Sys())
	}
	waitGone(t, -cmd.Process.Pid, "process group")
}

func TestRunGroupSIGTERMWithinGraceIsNotKilled(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := RunGroup(ctx, cmd, GroupOptions{Grace: 10 * time.Second})
	if err == nil || res.Stopped != StopContext || res.Killed {
		t.Fatalf("res=%+v err=%v, want a graceful SIGTERM stop", res, err)
	}
	if res.Duration >= 10*time.Second {
		t.Fatalf("graceful stop waited for the whole grace period: %v", res.Duration)
	}
}

func TestRunGroupAbortStopsLikeCancel(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	abort := make(chan struct{})
	close(abort)
	res, err := RunGroup(context.Background(), cmd, GroupOptions{Grace: time.Second, Abort: abort})
	if err == nil || res.Stopped != StopAbort {
		t.Fatalf("res=%+v err=%v, want StopAbort", res, err)
	}
}

func TestRunGroupNaturalExitIsUnchanged(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 3")
	res, err := RunGroup(context.Background(), cmd, GroupOptions{})
	var exitErr *exec.ExitError
	if res.Stopped != StopNone || !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("res=%+v err=%v, want natural exit 3", res, err)
	}
}

func TestExecRunProcessGroupCancelReportsContextCause(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Exec{}.Run(ctx, os.Args[0], []string{"-test.run=^$"}, Options{
			Env:          []string{helperEnv + "=spawn-grandchild", "TPLAITER_TEST_PIDFILE=" + pidFile},
			ProcessGroup: true,
			KillGrace:    time.Second,
		})
		done <- err
	}()
	_, grandchild := readPidPair(t, pidFile)
	cancel()
	runErr := <-done
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run error=%v, want context.Canceled in the chain", runErr)
	}
	var exitErr *ExitError
	if errors.As(runErr, &exitErr) {
		t.Fatalf("cancellation reported as an ordinary exit: %v", runErr)
	}
	waitGone(t, grandchild, "grandchild")
}

func TestExecRunSingleProcessCancelIsGraceful(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const grace = 200 * time.Millisecond
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := Exec{}.Run(ctx, os.Args[0], []string{"-test.run=^$"}, Options{
			Env:       []string{helperEnv + "=ignore-term", "TPLAITER_TEST_READY=" + ready},
			KillGrace: grace,
		})
		done <- err
	}()
	waitForFile(t, ready)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > testWait(t) {
		t.Fatalf("SIGTERM-ignoring child was not killed after the grace period (%v)", elapsed)
	}
}

func TestDefaultKillGraceIsTwoSeconds(t *testing.T) {
	if DefaultKillGrace != 2*time.Second {
		t.Fatalf("DefaultKillGrace=%v; docs/exit-codes.md and the MCP contract say 2s", DefaultKillGrace)
	}
}
