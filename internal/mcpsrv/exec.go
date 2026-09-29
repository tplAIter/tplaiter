package mcpsrv

import (
	"context"
	"errors"
	"os"
	"os/exec" //nolint:depguard // the MCP transport owns process-group lifecycle for the held child
	"path/filepath"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
)

var (
	// errTransportTimeout: the tool's own deadline expired.
	errTransportTimeout = errors.New("MCP_TIMEOUT")
	// errTransportCancelled: the client cancelled the request
	// (notifications/cancelled) or the server is shutting down.
	errTransportCancelled = errors.New("MCP_CANCELLED")
	errOutputLimit        = errors.New("MCP_OUTPUT_LIMIT")
)

const (
	maxToolOutput = 1 << 20
	maxToolStderr = 64 << 10
)

// timeoutClass selects one of the configured tool deadlines.
type timeoutClass int

const (
	shortCall timeoutClass = iota
	longCall
)

// Limits bounds every child process the server starts.
type Limits struct {
	// DefaultTimeout bounds quick tools (listing, inspection).
	DefaultTimeout time.Duration
	// LongTimeout bounds tools that render, fetch or build.
	LongTimeout time.Duration
	// KillGrace is the time a stopped child process group has between
	// SIGTERM and SIGKILL.
	KillGrace time.Duration
}

// DefaultLimits returns the production limits.
func DefaultLimits() Limits {
	return Limits{DefaultTimeout: 120 * time.Second, LongTimeout: 300 * time.Second, KillGrace: execx.DefaultKillGrace}
}

// SetLimits replaces the server limits; zero fields keep their defaults. It
// must be called before the server starts serving.
func (s *Server) SetLimits(l Limits) {
	d := DefaultLimits()
	if l.DefaultTimeout <= 0 {
		l.DefaultTimeout = d.DefaultTimeout
	}
	if l.LongTimeout <= 0 {
		l.LongTimeout = d.LongTimeout
	}
	if l.KillGrace <= 0 {
		l.KillGrace = d.KillGrace
	}
	s.limits = l
}

func (s *Server) timeout(class timeoutClass) time.Duration {
	if class == longCall {
		return s.limits.LongTimeout
	}
	return s.limits.DefaultTimeout
}

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

// runCLI runs one tplaiter child process for a tool call. Transport
// failures are reported as errTransportTimeout, errTransportCancelled,
// errOutputLimit or errTransportUnavailable; a completed child with a
// non-zero status is reported as *execx.ExitError.
func (s *Server) runCLI(ctx context.Context, cwd string, argv []string, timeout time.Duration) (execx.Result, error) {
	if s == nil || s.exe == "" {
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !s.installed && !s.direct {
		if s.runner == nil {
			return execx.Result{ExitCode: -1}, errTransportUnavailable
		}
		res, err := s.runner.Run(callCtx, s.exe, argv, execx.Options{Dir: cwd, Env: childEnvironment(), ProcessGroup: true, KillGrace: s.limits.KillGrace})
		if stopErr := stopCause(ctx, callCtx); stopErr != nil {
			return execx.Result{ExitCode: -1}, stopErr
		}
		return res, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	s.children.Add(1)
	s.mu.Unlock()
	defer s.children.Done()
	child := s.exe
	if s.installed {
		path, err := s.stage.launchPath()
		if err != nil {
			return execx.Result{ExitCode: -1}, errTransportUnavailable
		}
		child = path
	}
	// Cancellation is handled by execx.RunGroup, which stops the whole process
	// group (SIGTERM, grace, SIGKILL); exec.CommandContext cannot do that.
	cmd := exec.Command(child, argv...) //nolint:noctx // fixed launch path; argv is built by the server, never a shell
	cmd.Dir = cwd
	cmd.Env = s.childEnv
	cmd.Stdin = nil
	overflow := make(chan struct{}, 1)
	stdout, stderr := newBoundedBuffer(maxToolOutput, overflow), newBoundedBuffer(maxToolStderr, overflow)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	group, waitErr := execx.RunGroup(callCtx, cmd, execx.GroupOptions{Grace: s.limits.KillGrace, Abort: overflow})
	if cmd.Process == nil {
		return execx.Result{ExitCode: -1}, errTransportUnavailable
	}
	switch group.Stopped {
	case execx.StopContext:
		return execx.Result{ExitCode: -1}, stopCause(ctx, callCtx)
	case execx.StopAbort:
		return execx.Result{ExitCode: -1}, errOutputLimit
	case execx.StopNone:
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

// stopCause classifies why a call context ended: the client (or server
// shutdown) cancelled the parent request, or the tool's own deadline
// expired. It returns nil while callCtx is still live.
func stopCause(parent, callCtx context.Context) error {
	if callCtx.Err() == nil {
		return nil
	}
	if errors.Is(parent.Err(), context.Canceled) {
		return errTransportCancelled
	}
	return errTransportTimeout
}

// transportCode returns the fixed MCP code of a transport failure, or ""
// when the child completed (successfully or not).
func transportCode(res execx.Result, runErr error) string {
	switch {
	case errors.Is(runErr, errTransportTimeout):
		return "MCP_TIMEOUT"
	case errors.Is(runErr, errTransportCancelled):
		return "MCP_CANCELLED"
	case errors.Is(runErr, errOutputLimit):
		return "MCP_OUTPUT_LIMIT"
	case errors.Is(runErr, errTransportUnavailable):
		return "MCP_UNAVAILABLE"
	case res.ExitCode == -1:
		return "MCP_UNAVAILABLE"
	default:
		return ""
	}
}

func failed(res execx.Result, runErr error) bool { return res.ExitCode != 0 || runErr != nil }

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
