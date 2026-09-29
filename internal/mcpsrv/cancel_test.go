package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// helperEnv turns this test binary into a fake tplaiter child (see TestMain).
const helperEnv = "TPLAITER_TEST_HELPER"

// TestMain dispatches helper modes before the testing flags are parsed, so
// the binary can stand in for the tplaiter child regardless of the argv the
// server builds.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "spawn-grandchild":
		os.Exit(spawnGrandchild())
	case "envelope":
		// Print the envelope supplied by the test and exit with its status.
		_, _ = os.Stdout.WriteString(os.Getenv("TPLAITER_TEST_ENVELOPE"))
		code, _ := strconv.Atoi(os.Getenv("TPLAITER_TEST_EXIT"))
		os.Exit(code)
	case "flood":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", maxToolOutput+10))
		os.Exit(0)
	default:
		os.Exit(97)
	}
}

// spawnGrandchild starts `sh -c 'sleep 300'` in its own (inherited) process
// group, publishes "<leader pid> <grandchild pid>" and waits forever.
func spawnGrandchild() int {
	grandchild := exec.Command("/bin/sh", "-c", "sleep 300")
	if err := grandchild.Start(); err != nil {
		return 98
	}
	pidFile := os.Getenv("TPLAITER_TEST_PIDFILE")
	payload := fmt.Sprintf("%d %d", os.Getpid(), grandchild.Process.Pid)
	if err := os.WriteFile(pidFile+".tmp", []byte(payload), 0o600); err != nil {
		return 99
	}
	if err := os.Rename(pidFile+".tmp", pidFile); err != nil {
		return 99
	}
	_ = grandchild.Wait()
	time.Sleep(time.Hour)
	return 0
}

// directHelperServer returns a direct-transport server whose child is this
// test binary in helper mode.
func directHelperServer(t *testing.T, limits Limits, env ...string) *Server {
	t.Helper()
	exe, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	s := NewDirect(exe, "test")
	if s == nil {
		t.Fatal("NewDirect rejected an absolute executable")
	}
	s.SetLimits(limits)
	s.childEnv = append(capturedChildEnvironment(), env...)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func readPids(t *testing.T, path string) (leader, grandchild int) {
	t.Helper()
	deadline := time.Now().Add(waitBudget(t))
	for {
		if raw, err := os.ReadFile(path); err == nil {
			fields := strings.Fields(string(raw))
			if len(fields) == 2 {
				leader, _ = strconv.Atoi(fields[0])
				grandchild, _ = strconv.Atoi(fields[1])
				return leader, grandchild
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper did not publish its pids in %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requireGone waits until kill(target, 0) reports ESRCH (a killed orphan can
// linger as a zombie until init reaps it).
func requireGone(t *testing.T, target int, what string) {
	t.Helper()
	deadline := time.Now().Add(waitBudget(t))
	for {
		if err := syscall.Kill(target, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (%d) survived the stopped tool call", what, target)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitBudget(t *testing.T) time.Duration {
	budget := 30 * time.Second
	if deadline, ok := t.Deadline(); ok {
		if left := time.Until(deadline) / 2; left < budget {
			budget = left
		}
	}
	return budget
}

func transportDiagnostic(t *testing.T, res *mcp.CallToolResult) resultdto.Diagnostic {
	t.Helper()
	env := structuredEnvelope(t, res)
	if !res.IsError || env.Status != resultdto.StatusFailed || len(env.Diagnostics) != 1 {
		t.Fatalf("not a transport failure envelope: isError=%v %+v", res.IsError, env)
	}
	return env.Diagnostics[0]
}

func durationMs(t *testing.T, d resultdto.Diagnostic) int64 {
	t.Helper()
	switch v := d.Details["durationMs"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	default:
		t.Fatalf("diagnostic %s has no numeric durationMs: %#v", d.Code, d.Details)
		return 0
	}
}

// TestToolTimeoutStopsWholeGroup: the tool deadline yields MCP_TIMEOUT with
// durationMs, and neither the child's process group nor its grandchild
// survives.
func TestToolTimeoutStopsWholeGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	// The helper must start and publish its pids before the deadline fires.
	// A -race test binary under a loaded host (make verify runs every
	// package in parallel) can take well over a second to start, so the
	// deadline leaves room for that.
	const timeout = 3 * time.Second
	s := directHelperServer(t, Limits{DefaultTimeout: timeout, KillGrace: 500 * time.Millisecond},
		helperEnv+"=spawn-grandchild", "TPLAITER_TEST_PIDFILE="+pidFile)
	res := s.callStructured(context.Background(), resultdto.OperationRepoList, "", argvRepoList(), shortCall)
	leader, grandchild := readPids(t, pidFile)
	d := transportDiagnostic(t, res)
	if d.Code != "MCP_TIMEOUT" {
		t.Fatalf("code=%s, want MCP_TIMEOUT", d.Code)
	}
	if ms := durationMs(t, d); ms < timeout.Milliseconds() {
		t.Fatalf("durationMs=%d is shorter than the %v deadline", ms, timeout)
	}
	requireGone(t, -leader, "process group")
	requireGone(t, grandchild, "grandchild")
}

// TestClientCancelIsDistinctFromTimeout: cancelling the request context
// (what mcp-go does on notifications/cancelled) yields MCP_CANCELLED, not
// MCP_TIMEOUT, well before the tool deadline, and the group is gone.
func TestClientCancelIsDistinctFromTimeout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	s := directHelperServer(t, Limits{DefaultTimeout: time.Minute, KillGrace: 500 * time.Millisecond},
		helperEnv+"=spawn-grandchild", "TPLAITER_TEST_PIDFILE="+pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- s.callStructured(ctx, resultdto.OperationRepoList, "", argvRepoList(), shortCall)
	}()
	leader, grandchild := readPids(t, pidFile)
	cancelledAt := time.Now()
	cancel()
	res := <-done
	if elapsed := time.Since(cancelledAt); elapsed > 30*time.Second {
		t.Fatalf("cancel took %v", elapsed)
	}
	d := transportDiagnostic(t, res)
	if d.Code != "MCP_CANCELLED" {
		t.Fatalf("code=%s, want MCP_CANCELLED", d.Code)
	}
	if ms := durationMs(t, d); ms <= 0 {
		t.Fatalf("durationMs=%d", ms)
	}
	requireGone(t, -leader, "process group")
	requireGone(t, grandchild, "grandchild")
}

// TestDirectTransportPassesChildEnvelope: a child that prints a valid
// envelope and exits with a matching status is passed through unchanged.
func TestDirectTransportPassesChildEnvelope(t *testing.T) {
	stdout := envelopeJSON(t, resultdto.OperationTemplateLint, func(r *resultdto.Result) {
		r.Status = resultdto.StatusFailed
		r.Diagnostics = []resultdto.Diagnostic{{Code: "TPL-E-LINT-FAILED", Severity: "error", Message: "lint failures", Details: map[string]any{}}}
		_ = r.SetData(resultdto.TemplateLintData{Failed: true, Rows: []resultdto.TemplateLintRow{}})
	})
	s := directHelperServer(t, DefaultLimits(), helperEnv+"=envelope", "TPLAITER_TEST_ENVELOPE="+stdout, "TPLAITER_TEST_EXIT=1")
	res := s.callStructured(context.Background(), resultdto.OperationTemplateLint, "", argvLintTemplate("/tmp", ""), longCall)
	env := structuredEnvelope(t, res)
	if !res.IsError || env.Status != resultdto.StatusFailed || env.Diagnostics[0].Code != "TPL-E-LINT-FAILED" {
		t.Fatalf("isError=%v envelope=%+v", res.IsError, env)
	}
}

// TestDirectTransportOutputLimit: output beyond the bound stops the child
// with MCP_OUTPUT_LIMIT.
func TestDirectTransportOutputLimit(t *testing.T) {
	s := directHelperServer(t, DefaultLimits(), helperEnv+"=flood")
	res := s.callStructured(context.Background(), resultdto.OperationRepoList, "", argvRepoList(), shortCall)
	if d := transportDiagnostic(t, res); d.Code != "MCP_OUTPUT_LIMIT" {
		t.Fatalf("code=%s, want MCP_OUTPUT_LIMIT", d.Code)
	}
}

func TestNewDirectRejectsRelativeExecutable(t *testing.T) {
	if NewDirect("relative/tplaiter", "test") != nil {
		t.Fatal("relative executable accepted")
	}
}

func TestSetLimitsKeepsDefaultsForZeroFields(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	s.SetLimits(Limits{LongTimeout: time.Second})
	d := DefaultLimits()
	if s.limits.DefaultTimeout != d.DefaultTimeout || s.limits.LongTimeout != time.Second || s.limits.KillGrace != d.KillGrace {
		t.Fatalf("limits=%+v", s.limits)
	}
}
