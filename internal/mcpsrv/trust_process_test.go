package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"golang.org/x/sys/unix"
)

func TestInstalledTransportRejectsUnsafeExecutableAndSanitizesChildren(t *testing.T) {
	if NewInstalled("relative/tplaiter", "test", t.TempDir()) != nil {
		t.Fatal("relative executable accepted")
	}
	t.Setenv("HTTP_PROXY", "http://secret.invalid")
	t.Setenv("TPLAITER_HOME", "relative-home")
	t.Setenv("HOME", t.TempDir())
	env := childEnvironment()
	for _, value := range env {
		if value == "HTTP_PROXY=http://secret.invalid" || value == "TPLAITER_HOME=relative-home" {
			t.Fatalf("secret environment inherited: %q", value)
		}
	}
	for _, fixed := range []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=dumb", "NO_COLOR=1"} {
		if !containsEnvironment(env, fixed) {
			t.Fatalf("missing fixed child environment %q: %v", fixed, env)
		}
	}
	for _, value := range env {
		if strings.HasPrefix(value, "PATH=") || strings.HasPrefix(value, "LANG=") {
			continue
		}
		if !strings.Contains(value, "=") {
			t.Fatalf("malformed child environment entry: %q", value)
		}
	}
}

func TestBoundedTransportOutputDoesNotExposeCanary(t *testing.T) {
	b := newBoundedBuffer(maxToolOutput, nil)
	_, _ = b.Write(make([]byte, maxToolOutput+1))
	if !b.overflow || len(b.b) != maxToolOutput {
		t.Fatalf("bounded writer overflow=%v len=%d", b.overflow, len(b.b))
	}
	res := toolResult(execx.Result{Stdout: "secret-canary", ExitCode: 1}, errTransportUnavailable)
	if text := resultText(t, res); text != "MCP_UNAVAILABLE" {
		t.Fatalf("unsafe failure text: %q", text)
	}
	for _, tc := range []struct{ stderr, want string }{
		{"error: trustload: TRUST_ANCHOR_MISSING\n", "TRUST_ANCHOR_MISSING"},
		{"error: trustload: TRUST_PROVENANCE_UNAVAILABLE\nTRUST_ACTION_UNAVAILABLE\n", "TRUST_ACTION_UNAVAILABLE"},
		{"error: trustload: TRUST_PROVENANCE_UNAVAILABLE\nTRUST_EXECUTION_UNAVAILABLE\n", "TRUST_EXECUTION_UNAVAILABLE"},
		{"error: trustload: TRUST_ANCHOR_MISSING\nsecret-canary", "MCP_CLI_FAILED"},
		{"secret-canary TRUST_ANCHOR_MISSING", "MCP_CLI_FAILED"},
	} {
		got := resultText(t, toolResult(execx.Result{ExitCode: 1, Stderr: tc.stderr}, &execx.ExitError{ExitCode: 1}))
		if got != tc.want {
			t.Fatalf("diagnostic %q => %q, want %q", tc.stderr, got, tc.want)
		}
	}
}

// TestInstalledTransportHelperProcess is only an executable fixture for the
// installed runner tests below. It receives every mode through argv and has no
// access to the parent environment except the explicitly supplied marker.
func TestInstalledTransportHelperProcess(t *testing.T) {
	if os.Getenv("TPLAITER_T7_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "stdout":
		_, _ = fmt.Fprint(os.Stdout, "verified-output\n")
		_, _ = fmt.Fprint(os.Stderr, "stderr-canary")
	case "empty":
	case "stderr":
		_, _ = fmt.Fprint(os.Stderr, "secret-stderr-canary")
		os.Exit(7)
	case "overflow":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", maxToolOutput+1))
	case "block":
		if ready := os.Getenv("TPLAITER_T7_READY"); ready != "" {
			_ = os.WriteFile(ready, []byte("ready"), 0o600)
		}
		time.Sleep(time.Hour)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func installedTestServer(t *testing.T, extraEnv ...string) *Server {
	t.Helper()
	exe, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(exe); err == nil {
		t.Logf("staging helper executable size=%d", info.Size())
	}
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stage, err := newHeldStage(exe, scratch)
	if err != nil {
		if errors.Is(err, errTransportUnavailable) && runtime.GOOS != "darwin" {
			t.Skip("held-stage transport is not available on " + runtime.GOOS)
		}
		t.Fatal(err)
	}
	s := New(exe, "test", nil)
	s.installed = true
	s.stage = stage
	s.childEnv = append([]string{"PATH=/usr/bin:/bin", "LANG=C", "TPLAITER_T7_HELPER=1"}, extraEnv...)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func containsEnvironment(env []string, want string) bool {
	for _, value := range env {
		if value == want {
			return true
		}
	}
	return false
}

func helperArgs(mode string) []string {
	return []string{"-test.run=^TestInstalledTransportHelperProcess$", "--", mode}
}

func TestInstalledTransportBoundsOutputAndDiagnostics(t *testing.T) {
	s := installedTestServer(t)
	res, err := s.runCLI(context.Background(), "", helperArgs("stdout"), 10*time.Second)
	if err != nil || res.Stdout != "verified-output\n" || res.Stderr != "stderr-canary" {
		t.Fatalf("success result=%+v err=%v", res, err)
	}
	if text := resultText(t, toolResult(res, err)); text != "verified-output\n" {
		t.Fatalf("successful stderr leaked: %q", text)
	}
	res, err = s.runCLI(context.Background(), "", helperArgs("empty"), 10*time.Second)
	if err != nil || resultText(t, toolResult(res, err)) != "(команда завершилась успешно, вывод пуст)" {
		t.Fatalf("empty result=%+v err=%v", res, err)
	}
	for _, tc := range []struct{ mode, want string }{{"stderr", "MCP_CLI_FAILED"}, {"overflow", "MCP_OUTPUT_LIMIT"}} {
		res, err = s.runCLI(context.Background(), "", helperArgs(tc.mode), 10*time.Second)
		text := resultText(t, toolResult(res, err))
		if err == nil || text != tc.want || strings.Contains(text, "canary") {
			t.Fatalf("%s exposed failure result=%+v err=%v text=%q", tc.mode, res, err, text)
		}
	}
	res, err = s.runCLI(context.Background(), "", helperArgs("block"), 30*time.Millisecond)
	if err == nil || resultText(t, toolResult(res, err)) != "MCP_TIMEOUT" {
		t.Fatalf("timeout category result=%+v err=%v", res, err)
	}
	stagePath := filepath.Join(heldStageRoot(s.stage), "tplaiter")
	if err := os.Chmod(stagePath, 0o400); err != nil {
		t.Fatal(err)
	}
	res, err = s.runCLI(context.Background(), "", helperArgs("stdout"), 10*time.Second)
	if err == nil || resultText(t, toolResult(res, err)) != "MCP_UNAVAILABLE" {
		t.Fatalf("start failure category result=%+v err=%v", res, err)
	}
	if err := s.stage.Close(); err != nil {
		t.Fatal(err)
	}
	res, err = s.runCLI(context.Background(), "", helperArgs("stdout"), 10*time.Second)
	if err == nil || resultText(t, toolResult(res, err)) != "MCP_UNAVAILABLE" {
		t.Fatalf("closed stage accepted new launch result=%+v err=%v", res, err)
	}
}

func TestInstalledTransportCloseDrainsAndRejectsNewCalls(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	s := installedTestServer(t, "TPLAITER_T7_READY="+ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.runCLI(ctx, "", helperArgs("block"), time.Minute)
		done <- err
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	alsoClosed := make(chan error, 1)
	go func() { alsoClosed <- s.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before in-flight child drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case err := <-alsoClosed:
		t.Fatalf("concurrent Close returned before drain: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	res, err := s.runCLI(context.Background(), "", helperArgs("stdout"), 10*time.Second)
	if err == nil || resultText(t, toolResult(res, err)) != "MCP_UNAVAILABLE" {
		t.Fatalf("Close permitted a new call result=%+v err=%v", res, err)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled child returned success")
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close after drain: %v", err)
	}
	if err := <-alsoClosed; err != nil {
		t.Fatalf("concurrent Close after drain: %v", err)
	}
}

func TestDarwinHeldStageReplacementAndCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin held-stage mechanism")
	}
	root, err := os.MkdirTemp("/private/var/tmp", "tplaiter-t7-stage-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	source := filepath.Join(root, "source")
	original, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := stageChildExecutable(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("staged bytes=%q err=%v", got, err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stage remains after cleanup: %v", err)
	}
}

func TestDarwinHeldStageRejectsFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin held-stage mechanism")
	}
	root := t.TempDir()
	fifo := filepath.Join(root, "executable-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		stage, err := newHeldStage(fifo, root)
		if stage != nil {
			_ = stage.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO executable accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO executable blocked stage construction")
	}
}
