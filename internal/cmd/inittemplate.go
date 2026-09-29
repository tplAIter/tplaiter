package cmd

import (
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/inittemplate"
	"github.com/tplAIter/tplaiter/internal/resultdto"
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
			repoDir, err := inittemplate.Init(cmd.Context(), inittemplate.InitOptions{
				Name:   args[0],
				Dir:    dir,
				Multi:  multi,
				NoGit:  noGit,
				Runner: newRunner,
				Out:    humanOut(cmd),
			})
			if err != nil || !jsonMode(cmd) {
				return err
			}
			if abs, absErr := filepath.Abs(repoDir); absErr == nil {
				repoDir = abs
			}
			return emitData(cmd, resultdto.OperationTemplateInit, nil, resultdto.TemplateInitData{Name: args[0], Dir: repoDir, Multi: multi})
		},
	}
	f := c.Flags()
	f.StringVar(&dir, "dir", "", "target repository directory (defaults to ./<name>)")
	f.BoolVar(&multi, "multi", false, "multi-repository (repo.manifest.yaml + template in <name>/ subdirectory)")
	f.BoolVar(&noGit, "no-git", false, "skip git init and first commit")
	return withResult(c, resultdto.OperationTemplateInit)
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
				Out:       humanOut(cmd),
				Palette:   ui.Default(),
			})
			if err != nil {
				return err
			}
			failures := errors.New("lint-template: failures detected")
			if jsonMode(cmd) {
				return emitLintResult(cmd, res, failures)
			}
			if res.Failed {
				// Exit 1: lint findings (docs/exit-codes.md).
				return &ExitError{Code: 1, Err: failures}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&path, "path", ".", "template repository root")
	f.StringVar(&combo, "combo", "", "filter by combination name (exact match)")
	return withResult(c, resultdto.OperationTemplateLint)
}

// emitLintResult prints the lint table as template.lint data. Failures are
// findings: status failed, exit 1. Row details are not included because they
// quote template content; the human table on stderr has them.
func emitLintResult(cmd *cobra.Command, res *inittemplate.LintResult, failures error) error {
	data := resultdto.TemplateLintData{Failed: res.Failed, Rows: []resultdto.TemplateLintRow{}}
	for _, row := range res.Rows {
		data.Rows = append(data.Rows, resultdto.TemplateLintRow{Template: row.Template, Combo: row.Combo, OK: row.OK})
	}
	env := newResult(resultdto.OperationTemplateLint)
	if err := env.SetData(data); err != nil {
		return err
	}
	if !res.Failed {
		return emitResult(cmd, env, resultdto.ExitSuccess, nil)
	}
	env.Status = resultdto.StatusFailed
	env.Diagnostics = []resultdto.Diagnostic{{Code: "TPL-E-LINT-FAILED", Severity: "error", Message: "one or more template combinations failed lint", Details: map[string]any{}}}
	return emitResult(cmd, env, resultdto.ExitFinding, failures)
}
