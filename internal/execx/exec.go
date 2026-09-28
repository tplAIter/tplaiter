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
)

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

// Run executes a command through os/exec.CommandContext.
func (Exec) Run(ctx context.Context, name string, args []string, opts Options) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
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
	if opts.Signals != nil {
		runErr = runWithSignalForwarding(cmd, opts.Signals)
	} else {
		runErr = cmd.Run()
	}
	res := Result{Stdout: stdoutBuf.String(), Stderr: stderrBuf.String()}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
		return res, nil
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		return res, &ExitError{Name: name, Args: args, ExitCode: res.ExitCode, Stderr: res.Stderr}
	default:
		// Binary not found, process could not be created, etc. — a launch failure,
		// not an exit code. exitCode -1 signals "did not run".
		res.ExitCode = -1
		return res, fmt.Errorf("execx: run %q: %w", name, runErr)
	}
}

// LookPath finds a binary path through exec.LookPath.
func (Exec) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// runWithSignalForwarding starts cmd in a separate process group and, until it
// exits, forwards every signal received from signals to the whole group in the
// background (see [Options.Signals]). cmd.Run() is unsuitable here: signals
// require access to cmd.Process between Start and Wait, so Start/Wait are explicit.
//
// A process group (Setpgid), rather than cmd.Process.Signal alone, is used
// because the command is almost always `$SHELL -c "<run>"`: the direct child is
// the shell, not the actual program. Some shells (observed with system /bin/sh)
// defer a trapped signal until the current foreground command ends; a signal
// sent only to the shell may therefore not reach the actual command promptly.
// Setpgid moves the shell and all descendants into a new group with pgid equal
// to the shell PID; signaling the whole group (kill(-pgid, sig)) reaches the
// actual process directly, regardless of how its parent shell handles signals.
func runWithSignalForwarding(cmd *exec.Cmd, signals <-chan os.Signal) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return err
	}
	pgid := cmd.Process.Pid // Setpgid without an explicit Pgid makes pgid == leader PID.

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					return
				}
				forwardSignal(pgid, sig)
			case <-done:
				return
			}
		}
	}()

	return cmd.Wait()
}

// forwardSignal sends sig to the whole process group pgid (see
// [runWithSignalForwarding]). Errors (for example, the group already exiting
// when the signal is delivered) are intentionally ignored; cmd.Wait determines
// the command's final status in any case.
func forwardSignal(pgid int, sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(-pgid, s)
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
}
