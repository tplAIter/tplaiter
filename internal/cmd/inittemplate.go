package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/inittemplate"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func init() {
	registerCommand(newInitTemplateCmd)
	registerCommand(newLintTemplateCmd)
}

// newInitTemplateCmd — `tplaiter init-template <name>`: per owner requirement
// 2, generates an EMPTY template repository with all tooling (manifest, files/,
// generators, ai-config, environment, CI).
func newInitTemplateCmd() *cobra.Command {
	var (
		dir   string
		multi bool
		noGit bool
	)
	c := &cobra.Command{
		Use:   "init-template <name>",
		Short: "Create a template repository with all tooling",
		Long: "Generates an empty tplaiter-compatible template repository: " +
			"template.manifest.yaml skeleton with sample settings groups, files/ tree with " +
			"working minimal example, generator, ai-config, environment playbook, NOTES, " +
			"maintainer README, and GitHub Actions workflow with lint-template check.\n\n" +
			"--multi adds repo.manifest.yaml and places template in <name>/ subdirectory. " +
			"By default runs git init and first commit (--no-git disables this).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := inittemplate.Init(cmd.Context(), inittemplate.InitOptions{
				Name:   args[0],
				Dir:    dir,
				Multi:  multi,
				NoGit:  noGit,
				Runner: newRunner,
				Out:    cmd.OutOrStdout(),
			})
			return err
		},
	}
	f := c.Flags()
	f.StringVar(&dir, "dir", "", "target repository directory (defaults to ./<name>)")
	f.BoolVar(&multi, "multi", false, "multi-repository (repo.manifest.yaml + template in <name>/ subdirectory)")
	f.BoolVar(&noGit, "no-git", false, "skip git init and first commit")
	return c
}

// newLintTemplateCmd — `tplaiter lint-template`: a generic template-repository
// self-test (manifest validation plus trial renders of all edge setting
// combinations). Exit 1 on any failure.
func newLintTemplateCmd() *cobra.Command {
	var (
		path  string
		combo string
	)
	c := &cobra.Command{
		Use:   "lint-template",
		Short: "Self-test template repository across corner settings combinations",
		Long: "Finds template repository manifest(s) (single at root or multi via " +
			"repo.manifest.yaml/scan), validates each template, and runs trial renders " +
			"across all \"corner\" settings combinations: defaults, each select/" +
			"multiselect option, all toggles together (all-on), and full max. For each combo, " +
			"checks rendering, NOTES, generator parsing, ai-config, and YAML environment playbooks.\n\n" +
			"Prints table (template × combo × status); returns code 1 on failure.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := inittemplate.Lint(inittemplate.LintOptions{
				Path:      path,
				ComboName: combo,
				Out:       cmd.OutOrStdout(),
				Palette:   ui.Default(),
			})
			if err != nil {
				return err
			}
			if res.Failed {
				return &ExitError{Code: 1, Err: errors.New("lint-template: failures detected")}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&path, "path", ".", "template repository root")
	f.StringVar(&combo, "combo", "", "filter by combination name (exact match)")
	return c
}
