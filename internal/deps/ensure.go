package deps

import (
	"context"
	"errors"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// EnsureOptions configures [EnsureTools] for non-interactive scenarios
// (`tplater new`, CI).
type EnsureOptions struct {
	// AutoYes — automatically confirm installation without an interactive question
	// (the `--yes` CLI flag, SPEC-03 §4). Full interactive confirmation (huh) is
	// the survey task (C2/tp-U1); here AutoYes is the sole source of consent.
	AutoYes bool
	// SkipInstall completely disables installation offers — check only (corresponds
	// to `--no-deps-check` for installation; version checks still run for an honest report).
	SkipInstall bool
}

// ErrMissingRequiredTools is returned by [EnsureTools] when, after checking (and
// attempting installation), at least one required tool remains missing or does
// not satisfy its constraint. errors.Is distinguishes this from other orchestration errors.
var ErrMissingRequiredTools = errors.New("deps: отсутствуют обязательные инструменты окружения")

// EnsureTools — orchestration of checking and (optionally) installing tools for
// `tplater new` (SPEC-03 §4): check -> offer installation for missing/mismatched
// tools -> check again -> fail if required tools remain unavailable.
//
// Tools with required=false that remain unavailable only produce an out.Warn and
// do not affect the final error.
func EnsureTools(ctx context.Context, runner execx.Runner, out UI, tools []manifest.Tool, opts EnsureOptions) error {
	statuses := Check(ctx, runner, tools)

	missing := make([]ToolStatus, 0, len(statuses))
	for i, st := range statuses {
		if st.Found && st.Satisfies {
			continue
		}

		if !opts.SkipInstall {
			confirm := func() bool { return opts.AutoYes }
			if _, err := Install(ctx, runner, out, st.Tool, confirm); err != nil {
				// Generic recipes are closed. Do not expose an error whose text
				// could contain manifest-controlled values or process output.
				out.Warn("dependency installation unavailable")
			}
			st = Check(ctx, runner, []manifest.Tool{st.Tool})[0]
			statuses[i] = st
		}

		if st.Found && st.Satisfies {
			continue
		}

		if !st.Tool.Required {
			// The generic gate cannot attest an optional tool. Keep this UI
			// message fixed: names, paths, and status error text are all
			// manifest- or runner-controlled.
			out.Warn("optional dependency unavailable")
			continue
		}
		missing = append(missing, st)
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: required dependencies unavailable", ErrMissingRequiredTools)
	}
	return nil
}
