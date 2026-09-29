package execx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// ErrInterrupted marks a command that [RunInterruptible] stopped because this
// process received SIGINT or SIGTERM. Callers must treat it as fatal: an
// interrupted optional step must not be downgraded to a warning.
var ErrInterrupted = errors.New("execx: interrupted by signal")

// NestedKillGrace is the default grace [RunInterruptible] gives a stopped
// command group. It is shorter than [DefaultKillGrace], the grace a
// supervising process (the MCP server stopping a tool call) gives tplaiter
// itself, so the nested group is killed before an outer SIGKILL could make
// tplaiter exit and leave that group behind.
const NestedKillGrace = DefaultKillGrace / 2

// RunInterruptible runs a non-interactive command in its own process group
// (Options.ProcessGroup is forced on) and stops that group when this process
// receives SIGINT or SIGTERM.
//
// A process-group command is no longer in the terminal's foreground group, so
// an interactive Ctrl+C reaches only tplaiter. Without this wrapper tplaiter
// would die and leave the command running as an orphan. While the command
// runs, the signals cancel its context instead, which drives the regular
// SIGTERM, grace, SIGKILL sequence of [RunGroup] for the whole group; the
// returned error then wraps [ErrInterrupted]. A zero Options.KillGrace means
// [NestedKillGrace]. The signal handlers are removed before RunInterruptible
// returns.
func RunInterruptible(ctx context.Context, r Runner, name string, args []string, opts Options) (Result, error) {
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts.ProcessGroup = true
	if opts.KillGrace <= 0 {
		opts.KillGrace = NestedKillGrace
	}
	res, err := r.Run(runCtx, name, args, opts)
	if err != nil && runCtx.Err() != nil && ctx.Err() == nil {
		return res, fmt.Errorf("%w: %w", ErrInterrupted, err)
	}
	return res, err
}
