package selfupdate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// suggestInterval is the minimum interval between background version checks:
// once every 24h, not on every launch.
const suggestInterval = 24 * time.Hour

// MaybeSuggest performs a quiet background update check from the root command's
// PersistentPreRunE. It never interferes with or interrupts the current command:
//   - no more often than [suggestInterval] (the timestamp is
//     state.RunState.LastUpdateCheck; home and the current time now are passed
//     as arguments for testability rather than using time.Now() internally);
//   - `updates.check: false` in config.yaml — the check is skipped;
//   - any error (state/config reading or network) is silently swallowed, with
//     no output or interruption; the caller controls the ls-remote timeout via
//     ctx (see internal/cmd/selfupgrade.go);
//   - when outdated, it prints exactly one subdued line to out.
//
// current is the current CLI version (usually internal/cmd.resolveVersion()); it
// is passed in rather than computed here to avoid an import cycle.
// selfupdate<->cmd.
func MaybeSuggest(ctx context.Context, runner execx.Runner, home, current string, now time.Time, out io.Writer) {
	cfg, err := state.LoadConfig(home)
	if err != nil || !cfg.Updates.Check {
		return
	}

	rs, err := state.LoadRunState(home)
	if err != nil {
		return
	}
	if !rs.LastUpdateCheck.IsZero() && now.Sub(rs.LastUpdateCheck) < suggestInterval {
		return
	}

	// Update the timestamp BEFORE the network call: even a timeout or failed
	// check must not repeat on every launch; once per 24h means once per 24h
	// regardless of the outcome.
	rs.LastUpdateCheck = now
	_ = state.SaveRunState(home, rs)

	latest, err := LatestTag(ctx, runner, RepoURL())
	if err != nil || latest == "" {
		return
	}
	if Compare(current, latest) != CompareOutdated {
		return
	}

	p := ui.Default()
	fmt.Fprintln(out, p.Muted(fmt.Sprintf("доступна %s: tplater --upgrade", latest)))
}
