package execx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Compile-time check: Exec and RecordingRunner implement Runner.
var (
	_ Runner = Exec{}
	_ Runner = (*RecordingRunner)(nil)
)

func TestExec_Run_Success(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo hello"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "hello" {
		t.Errorf("Stdout = %q, want %q", got, "hello")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

func TestExec_Run_NonZeroExit(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo oops >&2; exit 3"}, Options{})
	if err == nil {
		t.Fatal("Run() expected error for non-zero exit")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run() error = %v, want *ExitError", err)
	}
	if exitErr.ExitCode != 3 {
		t.Errorf("ExitError.ExitCode = %d, want 3", exitErr.ExitCode)
	}
	if res.ExitCode != 3 {
		t.Errorf("Result.ExitCode = %d, want 3", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "oops") {
		t.Errorf("Stderr = %q, want to contain %q", res.Stderr, "oops")
	}
}

func TestExec_Run_BinaryNotFound(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "tplater-definitely-not-a-real-binary", nil, Options{})
	if err == nil {
		t.Fatal("Run() expected error for missing binary")
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("Run() error should not be *ExitError for a missing binary: %v", err)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1", res.ExitCode)
	}
}

func TestExec_Run_DirAndEnv(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "pwd; echo \"$TPLAITER_TEST_VAR\""}, Options{
		Dir: t.TempDir(),
		Env: []string{"TPLAITER_TEST_VAR=marker-123"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(res.Stdout, "marker-123") {
		t.Errorf("Stdout = %q, want to contain env var value", res.Stdout)
	}
}

func TestExec_Run_Stdin(t *testing.T) {
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "cat"}, Options{
		Stdin: strings.NewReader("piped-input"),
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "piped-input" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "piped-input")
	}
}

func TestExec_Run_StreamsToWriters(t *testing.T) {
	var stdout, stderr bytes.Buffer
	res, err := Exec{}.Run(context.Background(), "sh", []string{"-c", "echo out; echo err >&2"}, Options{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "out" {
		t.Errorf("streamed stdout = %q, want %q", stdout.String(), "out")
	}
	if strings.TrimSpace(stderr.String()) != "err" {
		t.Errorf("streamed stderr = %q, want %q", stderr.String(), "err")
	}
	// Result must accumulate complete output independently, not only what reached
	// the supplied writers.
	if strings.TrimSpace(res.Stdout) != "out" {
		t.Errorf("Result.Stdout = %q, want %q", res.Stdout, "out")
	}
}

// markerWaiter — io.Writer that accumulates everything written and closes ready
// as soon as the stream contains a marker. The signal-forwarding test uses it
// to wait for child readiness based on output rather than a timer (see [TestExec_Run_SignalForwarding]).
type markerWaiter struct {
	marker []byte

	mu    sync.Mutex
	buf   bytes.Buffer
	seen  bool
	ready chan struct{}
}

func newMarkerWaiter(marker string) *markerWaiter {
	return &markerWaiter{marker: []byte(marker), ready: make(chan struct{})}
}

func (w *markerWaiter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if !w.seen && bytes.Contains(w.buf.Bytes(), w.marker) {
		w.seen = true
		close(w.ready)
	}
	return len(p), nil
}

// TestExec_Run_SignalForwarding checks that a signal sent through Options.Signals
// reaches the child process (see [runWithSignalForwarding]). The child sh script
// traps SIGINT and exits with code 7; observing ExitError{ExitCode: 7} proves delivery.
//
// Synchronization is based on readiness, not a timer: the script prints the
// "trap-ready" marker to stdout immediately AFTER installing trap; the test
// waits for it through [markerWaiter] and only then sends the signal. Under a
// loaded parallel suite, the signal therefore cannot precede trap installation
// (previously sleep 200ms caused flakes: ExitCode -1 instead of 7). The script
// sleeps in a loop of short intervals rather than one long sleep: some shells
// (system /bin/sh — bash 3.2; see [runWithSignalForwarding]) defer trapped-signal
// handling until the current foreground command ends, so a signal arriving
// between sleeps could otherwise hang until the next sleep ended. Short sleeps
// cap the delay at ~100ms. The 5s timeouts are generous for CI load without
// allowing a forwarding regression to hang forever.
func TestExec_Run_SignalForwarding(t *testing.T) {
	sig := make(chan os.Signal, 1)
	waiter := newMarkerWaiter("trap-ready\n")

	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := Exec{}.Run(context.Background(), "sh", []string{
			"-c", "trap 'echo caught; exit 7' INT; echo trap-ready; while :; do sleep 0.1; done",
		}, Options{Signals: sig, Stdout: waiter})
		done <- outcome{res: res, err: err}
	}()

	select {
	case <-waiter.ready:
		// trap is installed — the signal can be sent.
	case out := <-done:
		t.Fatalf("процесс завершился до маркера готовности: res=%+v err=%v", out.res, out.err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for trap-ready marker from child process")
	}
	sig <- os.Interrupt

	select {
	case out := <-done:
		var exitErr *ExitError
		if !errors.As(out.err, &exitErr) {
			t.Fatalf("Run() error = %v, want *ExitError", out.err)
		}
		if exitErr.ExitCode != 7 {
			t.Errorf("ExitError.ExitCode = %d, want 7", exitErr.ExitCode)
		}
		if !strings.Contains(out.res.Stdout, "caught") {
			t.Errorf("Stdout = %q, want to contain %q (trap ran)", out.res.Stdout, "caught")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal-forwarded process to exit")
	}
}

func TestExec_LookPath(t *testing.T) {
	e := Exec{}
	if _, err := e.LookPath("tplater-definitely-not-a-real-binary"); err == nil {
		t.Error("LookPath() expected error for missing binary")
	}

	// "sh" must be available in PATH on every platform running the tests.
	path, err := e.LookPath("sh")
	if err != nil {
		t.Fatalf("LookPath(sh) error = %v", err)
	}
	if path == "" {
		t.Error("LookPath(sh) returned empty path")
	}
}

func TestExitError_Error(t *testing.T) {
	e := &ExitError{Name: "git", ExitCode: 1, Stderr: "fatal: not a git repository\nsome more detail"}
	got := e.Error()
	if !strings.Contains(got, "git") || !strings.Contains(got, "1") || !strings.Contains(got, "fatal: not a git repository") {
		t.Errorf("Error() = %q, missing expected substrings", got)
	}
	if strings.Contains(got, "some more detail") {
		t.Errorf("Error() = %q, should only include the first stderr line", got)
	}
}

// Check compatibility with exec.Error so callers can rely on standard-library
// types when needed.
func TestLookPath_ErrorType(t *testing.T) {
	_, err := exec.LookPath("tplater-definitely-not-a-real-binary")
	if err == nil {
		t.Skip("окружение неожиданно содержит такой бинарник")
	}
	var target *exec.Error
	if !errors.As(err, &target) {
		t.Fatalf("stdlib exec.LookPath error type changed, update assumptions: %v", err)
	}
}
