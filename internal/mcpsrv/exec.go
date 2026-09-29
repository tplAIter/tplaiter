package mcpsrv

import (
	"context"
	"errors"
	"os"
	"os/exec" //nolint:depguard // the MCP transport owns process-group lifecycle for the held child
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
)

var (
	errTransportTimeout = errors.New("MCP_TIMEOUT")
	errOutputLimit      = errors.New("MCP_OUTPUT_LIMIT")
)

const (
	defaultTimeout = 120 * time.Second
	longTimeout    = 300 * time.Second
	maxToolOutput  = 1 << 20
	maxToolStderr  = 64 << 10
)

type boundedBuffer struct {
	b        []byte
	limit    int
	overflow bool
	signal   chan<- struct{}
}

func newBoundedBuffer(limit int, signal chan<- struct{}) *boundedBuffer {
	return &boundedBuffer{limit: limit, signal: signal}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.b)+len(p) > b.limit {
		n := b.limit - len(b.b)
		if n > 0 {
			b.b = append(b.b, p[:n]...)
		}
		if !b.overflow {
			b.overflow = true
			if b.signal != nil {
				select {
				case b.signal <- struct{}{}:
				default:
				}
			}
		}
		return len(p), nil
	}
	b.b = append(b.b, p...)
	return len(p), nil
}

func (s *Server) runCLI(ctx context.Context, cwd string, argv []string, timeout time.Duration) (execx.Result, error) {
	if s == nil || s.exe == "" {
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !s.installed {
		if s.runner == nil {
			return execx.Result{ExitCode: -1}, errTransportUnavailable
		}
		return s.runner.Run(ctx, s.exe, argv, execx.Options{Dir: cwd, Env: childEnvironment()})
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	s.children.Add(1)
	s.mu.Unlock()
	defer s.children.Done()
	child, err := s.stage.launchPath()
	if err != nil {
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	// Cancellation is handled below by killing the whole process group, which
	// exec.CommandContext (single-process kill) cannot do.
	cmd := exec.Command(child, argv...) //nolint:noctx // fixed held-stage path; argv is built by the server, never a shell
	cmd.Dir = cwd
	cmd.Env = s.childEnv
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	overflow := make(chan struct{}, 1)
	stdout, stderr := newBoundedBuffer(maxToolOutput, overflow), newBoundedBuffer(maxToolStderr, overflow)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return execx.Result{ExitCode: -1}, errTransportTimeout
	case <-overflow:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return execx.Result{ExitCode: -1}, errOutputLimit
	}
	if stdout.overflow || stderr.overflow {
		return execx.Result{ExitCode: -1}, errOutputLimit
	}
	result := execx.Result{Stdout: string(stdout.b), Stderr: string(stderr.b), ExitCode: 0}
	if waitErr != nil {
		result.ExitCode = -1
		x := &exec.ExitError{}
		if errors.As(waitErr, &x) {
			result.ExitCode = x.ExitCode()
		}
		return result, &execx.ExitError{ExitCode: result.ExitCode}
	}
	return result, nil
}

func toolResult(res execx.Result, runErr error) *mcp.CallToolResult {
	if failed(res, runErr) {
		return mcp.NewToolResultError(formatFailure(res, runErr))
	}
	out := res.Stdout
	if strings.TrimSpace(out) == "" {
		out = "(команда завершилась успешно, вывод пуст)"
	}
	return mcp.NewToolResultText(out)
}
func failed(res execx.Result, runErr error) bool { return res.ExitCode != 0 || runErr != nil }
func formatFailure(res execx.Result, runErr error) string {
	switch {
	case errors.Is(runErr, errTransportTimeout):
		return "MCP_TIMEOUT"
	case errors.Is(runErr, errOutputLimit):
		return "MCP_OUTPUT_LIMIT"
	case errors.Is(runErr, errTransportUnavailable):
		return "MCP_UNAVAILABLE"
	case res.ExitCode == -1:
		return "MCP_UNAVAILABLE"
	case res.ExitCode != 0:
		if code := knownCLIError(res.Stderr); code != "" {
			return code
		}
		return "MCP_CLI_FAILED"
	default:
		return "MCP_UNAVAILABLE"
	}
}

// Only an entire fixed Cobra diagnostic may become a trust code. In
// particular, raw child stderr or a substring from a hostile path is never
// returned to the MCP caller.
func knownCLIError(stderr string) string {
	for _, code := range []string{"TRUST_ACTION_UNAVAILABLE", "TRUST_EXECUTION_UNAVAILABLE"} {
		if stderr == "error: trustload: TRUST_PROVENANCE_UNAVAILABLE\n"+code+"\n" {
			return code
		}
	}
	for _, code := range []string{
		"TRUST_ACTION_UNAVAILABLE", "TRUST_ANCHOR_MISSING", "TRUST_CONFIG_INVALID",
		"TRUST_DOWNGRADE_DENIED", "TRUST_EVIDENCE_MISSING", "TRUST_EVIDENCE_TAMPERED",
		"TRUST_EXPIRED", "TRUST_PIN_MISMATCH", "TRUST_PROFILE_INVALID",
		"TRUST_LIFECYCLE_UNAVAILABLE", "TRUST_PROTECTED_UNAVAILABLE", "TRUST_PROVENANCE_UNAVAILABLE",
		"TRUST_RUNTIME_INVALID", "TRUST_SOURCE_ADAPTER_UNSUPPORTED",
	} {
		for _, prefix := range []string{"error: ", "error: trustload: ", "error: bootstrap: ", "error: trustverify: "} {
			if stderr == prefix+code+"\n" {
				return code
			}
		}
	}
	return ""
}

func resolveWorkDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errTransportUnavailable
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return "", errTransportUnavailable
	}
	return abs, nil
}

func resolveTargetDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errTransportUnavailable
	}
	info, err := os.Stat(filepath.Dir(abs))
	if err != nil || !info.IsDir() {
		return "", errTransportUnavailable
	}
	return abs, nil
}

func capturedChildEnvironment() []string {
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=dumb", "NO_COLOR=1"}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "TPLAITER_HOME", "TMPDIR"} {
		if v, ok := os.LookupEnv(key); ok && validLocation(v) {
			env = append(env, key+"="+v)
		}
	}
	return env
}

func validLocation(v string) bool {
	return len([]byte(v)) > 0 && len([]byte(v)) <= 4096 && filepath.IsAbs(v) && filepath.Clean(v) == v && v != "/" && !strings.ContainsAny(v, "\x00\n\r")
}
func childEnvironment() []string { return capturedChildEnvironment() }
