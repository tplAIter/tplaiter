package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// DefaultKillGrace is how long a cancelled command (and, in process-group
// mode, its whole group) has between SIGTERM and SIGKILL.
const DefaultKillGrace = 2 * time.Second

// ExitError wraps a non-zero command exit code. errors.As lets callers
// distinguish "the command ran and returned non-zero" from "the command could
// not be started at all" (the latter is returned as-is, without wrapping).
type ExitError struct {
	Name     string
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s: exit code %d: %s", e.Name, e.ExitCode, firstLine(e.Stderr))
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// Exec — [Runner] implementation backed by os/exec. Its zero value is ready to use.
type Exec struct{}

// Run executes a command through os/exec.
//
// Cancellation is graceful: when ctx ends, the command receives SIGTERM and
// has Options.KillGrace (default [DefaultKillGrace]) to exit before SIGKILL.
// In process-group mode (Options.ProcessGroup or Options.Signals) the signals
// go to the whole group, so grandchildren (`$SHELL -c` pipelines, git
// helpers) are terminated as well; otherwise only the direct child is
// signalled, which keeps it in the terminal's foreground group so that
// interactive prompts keep working.
func (Exec) Run(ctx context.Context, name string, args []string, opts Options) (Result, error) {
	grace := opts.KillGrace
	if grace <= 0 {
		grace = DefaultKillGrace
	}
	group := opts.ProcessGroup || opts.Signals != nil

	var cmd *exec.Cmd
	if group {
		// The group is cancelled explicitly by RunGroup, which exec.CommandContext
		// (single-process kill) cannot do.
		cmd = exec.Command(name, args...) //nolint:noctx // cancellation is handled by RunGroup
	} else {
		cmd = exec.CommandContext(ctx, name, args...)
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = grace
	}
	cmd.Dir = opts.Dir
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if opts.Stdout != nil {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, opts.Stdout)
	}
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&stderrBuf, opts.Stderr)
	}

	var runErr error
	stopped := false
	if group {
		var gr GroupResult
		gr, runErr = RunGroup(ctx, cmd, GroupOptions{Grace: grace, Signals: opts.Signals})
		stopped = gr.Stopped != StopNone
	} else {
		runErr = cmd.Run()
	}
	res := Result{Stdout: stdoutBuf.String(), Stderr: stderrBuf.String()}
	if stopped {
		// The group was stopped because ctx ended. Whatever status the leader
		// managed to report (it may even win the race and exit 0 after its
		// children died), the outcome is the cancellation.
		res.ExitCode = -1
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Exited() {
			res.ExitCode = ws.ExitStatus()
		}
		return res, fmt.Errorf("execx: %q stopped: %w", name, context.Cause(ctx))
	}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
		return res, nil
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		if ctxErr := ctx.Err(); ctxErr != nil {
			// A cancelled command's exit status is a consequence of the
			// cancellation; report the cause so callers can tell a timeout
			// from a cancel.
			return res, fmt.Errorf("execx: %q stopped: %w", name, ctxErr)
		}
		return res, &ExitError{Name: name, Args: args, ExitCode: res.ExitCode, Stderr: res.Stderr}
	default:
		// Binary not found, process could not be created, etc. — a launch failure,
		// not an exit code. exitCode -1 signals "did not run".
		res.ExitCode = -1
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(runErr, ctxErr) {
			return res, fmt.Errorf("execx: %q stopped: %w", name, errors.Join(ctxErr, runErr))
		}
		return res, fmt.Errorf("execx: run %q: %w", name, runErr)
	}
}

// LookPath finds a binary path through exec.LookPath.
func (Exec) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// StopReason says why [RunGroup] stopped a process group early.
type StopReason int

const (
	// StopNone: the group leader exited on its own.
	StopNone StopReason = iota
	// StopContext: the context ended (deadline or cancellation).
	StopContext
	// StopAbort: GroupOptions.Abort fired (for example an output limit).
	StopAbort
)

// GroupOptions configures [RunGroup].
type GroupOptions struct {
	// Grace is the time between SIGTERM and SIGKILL; zero means
	// [DefaultKillGrace].
	Grace time.Duration
	// Abort, when it receives or is closed, stops the group like a context
	// cancellation.
	Abort <-chan struct{}
	// Signals are forwarded to the whole group while it runs.
	Signals <-chan os.Signal
}

// GroupResult describes how [RunGroup] finished.
type GroupResult struct {
	Stopped StopReason
	// Killed is true when the group had to be sent SIGKILL because it
	// outlived the grace period.
	Killed bool
	// Duration is the wall-clock time from start to reaping the leader.
	Duration time.Duration
}

// RunGroup starts cmd as the leader of a new process group and waits for it.
//
// When ctx ends or opts.Abort fires, the whole group receives SIGTERM; the
// group then has opts.Grace to exit before SIGKILL. After the leader has been
// reaped, any remaining group member (a grandchild that ignored SIGTERM or
// was orphaned) is killed as well, so a stopped command never leaves
// descendants behind. cmd must not have been started and must not set
// SysProcAttr.
func RunGroup(ctx context.Context, cmd *exec.Cmd, opts GroupOptions) (GroupResult, error) {
	grace := opts.Grace
	if grace <= 0 {
		grace = DefaultKillGrace
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return GroupResult{}, err
	}
	pgid := cmd.Process.Pid // Setpgid without an explicit Pgid makes pgid == leader PID.

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var result GroupResult
	var waitErr error
	for waiting := true; waiting; {
		select {
		case waitErr = <-done:
			waiting = false
		case sig, ok := <-opts.Signals:
			if !ok {
				opts.Signals = nil
				continue
			}
			forwardSignal(pgid, sig)
		case <-ctx.Done():
			result.Stopped = StopContext
			result.Killed, waitErr = terminateGroup(pgid, done, grace)
			waiting = false
		case <-opts.Abort:
			result.Stopped = StopAbort
			result.Killed, waitErr = terminateGroup(pgid, done, grace)
			waiting = false
		}
	}
	result.Duration = time.Since(start)
	if result.Stopped != StopNone {
		// The leader is gone; make sure no member of its group survives it.
		reapGroup(pgid)
	}
	return result, waitErr
}

// terminateGroup sends SIGTERM to the group, waits up to grace for the
// leader, then escalates to SIGKILL. It returns the leader's wait error.
func terminateGroup(pgid int, done <-chan error, grace time.Duration) (bool, error) {
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return false, err
	case <-timer.C:
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return true, <-done
}

// reapGroup kills whatever is left of group pgid after its leader exited.
// Signalling a group that no longer exists fails with ESRCH, which is the
// expected outcome.
func reapGroup(pgid int) {
	if err := syscall.Kill(-pgid, 0); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
}

// forwardSignal sends sig to the whole process group pgid. Errors (for
// example, the group already exiting when the signal is delivered) are
// intentionally ignored; the leader's wait determines the final status.
func forwardSignal(pgid int, sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(-pgid, s)
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
}
