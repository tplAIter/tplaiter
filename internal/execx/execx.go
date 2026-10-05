// Package execx — mockable layer for launching external processes.
//
// tplaiter constantly orchestrates external tools (git, glab, gh, brew, ansible,
// arbitrary manifest shell commands). All this code must use [Runner], rather
// than os/exec directly, so tests can substitute [RecordingRunner] without
// touching the real environment.
package execx

import (
	"context"
	"io"
	"os"
	"time"
)

// Result — result of executing one command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Options — optional command-run parameters.
type Options struct {
	// Dir — command working directory. Empty means the process's current directory.
	Dir string
	// Env — additional "KEY=VALUE" environment variables appended to os.Environ()
	// (not replacing it). An empty slice leaves the environment unchanged.
	Env []string
	// Stdin — data source for command stdin. nil means stdin is not connected.
	Stdin io.Reader
	// Stdout/Stderr — optional writers for streaming command output as it appears
	// (for example, into a UI log). The result is still accumulated completely in
	// Result.Stdout/Stderr regardless of whether these writers are set.
	Stdout io.Writer
	Stderr io.Writer
	// Signals — optional OS-signal channel (usually created by the caller through
	// os/signal.Notify) that Run forwards to the launched process until it exits.
	// It is needed by interactive long-running commands (for example, `tplaiter run
	// dev`) so Ctrl+C/SIGTERM caught by tplaiter do not silently terminate it
	// (leaving the child orphaned), but reach the child normally and give it a
	// chance for graceful shutdown. nil (the default) forwards no signals.
	Signals <-chan os.Signal
	// ProcessGroup runs the command as the leader of its own process group.
	// Cancellation (ctx) then terminates the whole group — SIGTERM, KillGrace,
	// SIGKILL — so no grandchild survives. Use it for non-interactive commands
	// that spawn their own children (hooks, `$SHELL -c` scripts). A group is
	// not in the terminal foreground, so interactive prompts must not use it.
	// A non-nil Signals implies ProcessGroup.
	ProcessGroup bool
	// KillGrace is the time a cancelled command has between SIGTERM and
	// SIGKILL; zero means [DefaultKillGrace].
	KillGrace time.Duration
}

// Runner executes external commands. Implementations are [Exec] (real os/exec)
// and [RecordingRunner] (test double with scripted responses and call recording).
type Runner interface {
	// Run starts name with args and waits for completion. An error is returned for
	// launch failures (binary not found) and non-zero exit codes (see [ExitError]);
	// callers almost always must check err, not only res.ExitCode.
	Run(ctx context.Context, name string, args []string, opts Options) (Result, error)
	// LookPath finds the full path to name in PATH (analogous to exec.LookPath).
	LookPath(name string) (string, error)
}
