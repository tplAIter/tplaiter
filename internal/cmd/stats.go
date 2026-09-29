package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func init() {
	registerCommand(newStatsCmd)
}

// newStatsCmd creates `tplater stats`: a drift report comparing the generated
// project with a clean render of the pinned template version — file statuses,
// percentage of changed lines (LCS), updateability classification
// (auto/conflict-prone/manual-only), total drift score, and broken anchors.
func newStatsCmd() *cobra.Command {
	var asJSON bool

	c := &cobra.Command{
		Use:   "stats",
		Short: "Show project drift from template (drift-score)",
		Long: "Compares a clean render of the pinned template version+answers (baseline) with the " +
			"project working tree; for each file — status (identical/modified/deleted/extra), " +
			"percentage of changed lines (LCS), and updateability class — auto (update will merge cleanly), " +
			"conflict-prone (template historically modified this file), or manual-only (deleted baseline file, " +
			"broken CODEGEN anchor, or edit in copyWithoutRender artifact).\n\n" +
			"Outputs total drift-score 0..100, top-10 files by drift, count of extra files and broken " +
			"anchors. --json provides a stable machine-readable schema for template operations dashboards.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			home, _, err := state.EnsureHome()
			if err != nil {
				return err
			}

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: stats: determining working directory: %w", err)
			}

			return stats.Run(cmd.Context(), stats.Deps{
				Manager: mgr,
				Home:    home,
				Out:     cmd.OutOrStdout(),
				Err:     cmd.ErrOrStderr(),
				Palette: ui.Default(),
			}, stats.Options{
				StartDir: cwd,
				JSON:     asJSON,
			})
		},
	}

	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable JSON report")
	return c
}
