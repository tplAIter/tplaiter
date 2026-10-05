package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/contribute"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// contributeRunner — runner for glab/gh commands used by `tplaiter upgrade`. A
// package variable replaced with execx.RecordingRunner in tests (like repoRunner).
var contributeRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newUpgradeCmd)
}

// newUpgradeCmd creates `tplaiter upgrade`: the reverse flow, where improvements
// in the generated project are proposed to the template through an MR/PR.
func newUpgradeCmd() *cobra.Command {
	var (
		files []string
		title string
		draft bool
		patch bool
		yes   bool
	)

	c := &cobra.Command{
		Use:   "upgrade",
		Short: "Propose project improvements to template (MR/PR)",
		Long: "Compares the project working tree with a clean render of the pinned template version " +
			"(baseline, like `tplaiter stats`) and proposes changed files back to the template repository. " +
			"Candidates are modified baseline files (go.mod/go.sum excluded as noisy); " +
			"extra files are added only with explicit --files <glob>. Selected files are de-parametrized " +
			"(slug/module/project name → placeholders `{{ .Project.* }}`), placed in the template `.tmpl` " +
			"source tree in a new cache-clone branch, then opens an MR (`glab`) / PR (`gh`) depending on " +
			"repository type.\n\n" +
			"Conditional settings blocks are not restored: a file from a conditional vertical is marked " +
			"with a TPLATER-REVIEW comment for manual maintainer review. For repositories without " +
			"API access (or plain git), use --patch — instead of push+MR, generates a series of " +
			"`git format-patch` files in ./tplater-upgrade-<date>/. No direct pushes to protected branches.",
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
				return fmt.Errorf("cmd: upgrade: determining working directory: %w", err)
			}

			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			var picker contribute.FilePicker
			if interactive {
				picker = contribute.HuhPicker{In: cmd.InOrStdin(), Out: cmd.OutOrStdout()}
			} else {
				picker = contribute.ScriptedPicker{} // non-interactive — all candidates.
			}

			_, err = contribute.Upgrade(cmd.Context(), contribute.Deps{
				Manager: mgr,
				Runner:  contributeRunner,
				Home:    home,
				Out:     cmd.OutOrStdout(),
				Err:     cmd.ErrOrStderr(),
				Palette: ui.Default(),
				Picker:  picker,
			}, contribute.Options{
				StartDir: cwd,
				Files:    files,
				Title:    title,
				Draft:    draft,
				Patch:    patch,
				Yes:      yes || !interactive,
			})
			return err
		},
	}

	f := c.Flags()
	f.StringArrayVar(&files, "files", nil, "glob of extra files to include (repeatable)")
	f.StringVar(&title, "title", "", "MR/PR title")
	f.BoolVar(&draft, "draft", false, "open MR/PR as draft")
	f.BoolVar(&patch, "patch", false, "generate git format-patch instead of push+MR")
	f.BoolVar(&yes, "yes", false, "do not ask questions (select all candidates)")
	return c
}
