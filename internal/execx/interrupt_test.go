package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestRunInterruptibleStopsGroupOnParentSIGINT interrupts the test process
// itself while a `/bin/sh -c` command with a background grandchild runs, and
// asserts that the whole command group is gone and the error is marked as
// interrupted. Without RunInterruptible the group would survive its parent.
func TestRunInterruptibleStopsGroupOnParentSIGINT(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	script := `sleep 300 & echo "$$ $!" > "` + pidFile + `.tmp" && mv "` + pidFile + `.tmp" "` + pidFile + `"; wait`

	type outcome struct{ err error }
	done := make(chan outcome, 1)
	go func() {
		_, err := RunInterruptible(context.Background(), Exec{}, "/bin/sh", []string{"-c", script}, Options{KillGrace: testWait(t)})
		done <- outcome{err}
	}()

	fields := strings.Fields(string(waitForFile(t, pidFile)))
	if len(fields) != 2 {
		t.Fatalf("malformed pid file %q", fields)
	}
	pgid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := syscall.Getpgid(grandchild); err != nil || got != pgid {
		t.Fatalf("grandchild pgid = %d, %v; want %d", got, err, pgid)
	}

	// The handler is installed before the command starts, so this SIGINT
	// cancels the run instead of terminating the test binary.
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if !errors.Is(res.err, ErrInterrupted) {
		t.Fatalf("err = %v; want ErrInterrupted", res.err)
	}
	waitGone(t, -pgid, "hook process group")
	waitGone(t, grandchild, "hook grandchild")
}

// TestRunInterruptibleParentCancelIsNotInterrupt keeps ErrInterrupted for
// signals only: a cancelled caller context reports the cancellation.
func TestRunInterruptibleParentCancelIsNotInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunInterruptible(ctx, Exec{}, "/bin/sh", []string{"-c", "sleep 300"}, Options{})
	if err == nil || errors.Is(err, ErrInterrupted) {
		t.Fatalf("err = %v; want a cancellation that is not ErrInterrupted", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}
