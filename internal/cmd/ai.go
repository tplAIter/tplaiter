package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// aiTargetsFlag — `--targets` flag for `tplaiter ai gen` (empty → all
// targets in the source config.json; see [aiconfig.RenderOptions.Targets]).
var aiTargetsFlag []string

func init() {
	registerCommand(newAICmd)
}

// newAICmd creates the `tplaiter ai` command: generate/list/validate the
// project's AI configuration (CLAUDE.md/.cursor/**/AGENTS.md/GEMINI.md)
// from the copied .tplaiter/ai-config directory (contract with /).
func newAICmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ai",
		Short: "AI configuration for the project (CLAUDE.md, .cursor/**, AGENTS.md, GEMINI.md)",
		Long: "Works with the ai-config directory copy that `tplaiter new` places in the project " +
			"as .tplaiter/ai-config. Modules are gated by a `when` condition (§3.2) based on " +
			"current project settings — a module without when is always active.",
	}
	c.AddCommand(newAIGenCmd(), newAIListCmd(), newAIValidateCmd())
	return c
}

// loadAIContext finds the project root, resolves the template manifest, and
// opens the .tplaiter/ai-config source. It returns a clear error if the
// directory is missing (the template does not include aiConfig or has not
// copied it yet).
func loadAIContext() (tpl *manifest.Template, values settings.Values, root string, src *aiconfig.Source, err error) {
	tpl, proj, root, err := loadRunContext()
	if err != nil {
		return nil, nil, "", nil, err
	}

	dir := filepath.Join(root, aiconfig.AIConfigRelPath)
	if _, statErr := os.Stat(dir); statErr != nil {
		return nil, nil, "", nil, fmt.Errorf(
			"ai: directory %s not found — template does not include aiConfig or project was created without it", aiconfig.AIConfigRelPath,
		)
	}

	src, err = aiconfig.Load(dir)
	if err != nil {
		return nil, nil, "", nil, err
	}
	return tpl, settingsValues(proj.Settings), root, src, nil
}

// newAIGenCmd creates `tplaiter ai gen`.
func newAIGenCmd() *cobra.Command {
	c := &cobra.Command{
		// Preserved from the former name-based switch, which matched every command
		// named "gen": `ai gen` is refused as a legacy action. Revisit with trusted
		// action execution (U13).
		Annotations: prerunAnnotations(prerunLegacyAction),

		Use:   "gen",
		Short: "Generate AI artifacts in project root",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, values, root, src, err := loadAIContext()
			if err != nil {
				return err
			}

			res, err := src.Render(aiconfig.RenderOptions{
				TargetRoot: root,
				Values:     values,
				Targets:    aiTargetsFlag,
			})
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return emitAIResult(cmd, root, res)
			}
			return printAIResult(cmd, res)
		},
	}
	c.Flags().StringSliceVar(&aiTargetsFlag, "targets", nil,
		"limit generation to list of targets (default — all config.targets from source)")
	return withResult(c, resultdto.OperationAIGen)
}

// emitAIResult prints the written and skipped AI artifacts as ai.gen data;
// written files are also the envelope changes.
func emitAIResult(cmd *cobra.Command, root string, res *aiconfig.Result) error {
	env := newResult(resultdto.OperationAIGen)
	env.Project = projectAt(root)
	for _, f := range res.Written {
		env.Changes = append(env.Changes, resultdto.Change{Path: f, Action: "write"})
	}
	env.Summary.FilesChanged = len(res.Written)
	if len(res.Written) > 0 {
		env.Status = resultdto.StatusChanges
	}
	if err := env.SetData(resultdto.AIGenData{Written: nonNil(res.Written), SkippedProtected: nonNil(res.SkippedProtected)}); err != nil {
		return err
	}
	return emitResult(cmd, env, resultdto.ExitSuccess, nil)
}

// printAIResult prints written and skipped (protected 99-*) files.
func printAIResult(cmd *cobra.Command, res *aiconfig.Result) error {
	out := cmd.OutOrStdout()
	for _, f := range res.Written {
		fmt.Fprintf(out, "written %s\n", f)
	}
	for _, f := range res.SkippedProtected {
		fmt.Fprintf(out, "skipped %s (project extension 99-*)\n", f)
	}
	return nil
}

// newAIListCmd creates `tplaiter ai list`.
func newAIListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List of ai-config modules (id/title/activation/when/available)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, values, _, src, err := loadAIContext()
			if err != nil {
				return err
			}
			return printAIList(cmd, src, values)
		},
	}
}

// printAIList prints the ID/TITLE/ACTIVATION/WHEN table.
func printAIList(cmd *cobra.Command, src *aiconfig.Source, values settings.Values) error {
	out := cmd.OutOrStdout()
	if len(src.Modules) == 0 {
		fmt.Fprintln(out, "ai-config source does not declare modules")
		return nil
	}

	active, err := src.Filter(values)
	if err != nil {
		return err
	}
	activeIDs := make(map[string]bool, len(active))
	for _, m := range active {
		activeIDs[m.ID] = true
	}

	modules := append([]aiconfig.LoadedModule(nil), src.Modules...)
	sort.Slice(modules, func(i, j int) bool { return modules[i].ID < modules[j].ID })

	pal := ui.Default()
	table := ui.NewTable("ID", "TITLE", "ACTIVATION", "WHEN")
	for _, m := range modules {
		when := m.When
		switch {
		case when == "":
			// No when means the module is always active; leave the column empty.
		case activeIDs[m.ID]:
			when = ui.StatusIcon(pal, ui.StatusOK) + " " + when
		default:
			when = ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted(when+" — unavailable with current settings")
		}
		table.AddRow(m.ID, m.Title, m.Activation, when)
	}
	fmt.Fprintln(out, table.RenderStyled(pal))
	return nil
}

// newAIValidateCmd creates `tplaiter ai validate`. The template manifest is
// resolved through the same source chain as `tplaiter run`/`gen` ([loadRunContext]
// → [project.LoadManifestForProject]): the repository cache is currently always
// unavailable, so .tplaiter/manifest.snapshot.yaml is used in practice — a
// missing snapshot produces a clear error ([project.ErrNoManifest]) without
// separate handling.
func newAIValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate ai-config source against project template manifest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, _, _, src, err := loadAIContext()
			if err != nil {
				return err
			}
			if err := src.Validate(tpl); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ai-config is valid")
			return nil
		},
	}
}
