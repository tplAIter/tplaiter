package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

func init() {
	registerCommand(newSettingsCmd)
}

// newSettingsCmd creates `tplater settings`: viewing and changing project
// settings with the same 3-way mechanism as `tplater update`, but on the
// current template version.
func newSettingsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "settings",
		Short: "View and modify project settings",
		Long: "Manages settings for the generated project. " +
			"`list` shows current values; `set group=value` changes them using the same " +
			"3-way merge mechanism as `update` (changing a select value removes the old " +
			"vertical of files and adds the new one; local edits are preserved or produce " +
			"conflict markers); `edit <group>` re-prompts one group interactively. " +
			"Template version and hooks are not affected — only re-rendering with new values.",
	}
	c.AddCommand(newSettingsListCmd())
	c.AddCommand(newSettingsSetCmd())
	c.AddCommand(newSettingsEditCmd())
	return c
}

// newSettingsListCmd creates `tplater settings list`.
func newSettingsListCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Use:   "list",
		Short: "Show current project settings values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: working directory: %w", err)
			}
			if jsonMode(cmd) {
				return emitSettingsShow(cmd, d.Home, cwd)
			}
			return settingscmd.List(d, settingscmd.Options{StartDir: cwd})
		},
	}, resultdto.OperationSettingsShow)
}

// emitSettingsShow prints the resolved project settings as settings.show
// data (the same values `settings list` renders as a table).
func emitSettingsShow(cmd *cobra.Command, home, cwd string) error {
	root, proj, err := project.FindRoot(cwd)
	if err != nil {
		return err
	}
	tpl, _, err := project.LoadManifestForProject(root, proj, home)
	if err != nil {
		return err
	}
	resolved, err := settings.Resolve(tpl, renderref.Values(proj.Settings))
	if err != nil {
		return fmt.Errorf("settings list: %w", err)
	}
	values := map[string]any{}
	for k, v := range resolved.Values {
		values[k] = v
	}
	data := resultdto.SettingsShowData{
		Template: resultdto.TemplateRef{Repo: proj.Template.Repo, Name: proj.Template.Name, Version: proj.Template.Version},
		Settings: values,
	}
	return emitData(cmd, resultdto.OperationSettingsShow, projectAt(root), data)
}

// newSettingsSetCmd creates `tplater settings set group=value [...]`.
func newSettingsSetCmd() *cobra.Command {
	var (
		dryRun bool
		yes    bool
	)
	c := &cobra.Command{
		Use:   "set group=value [group2=value2 ...]",
		Short: "Modify project settings (3-way merge on current version)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: working directory: %w", err)
			}
			opts := settingscmd.Options{
				StartDir: cwd,
				Pairs:    args,
				DryRun:   dryRun,
				Yes:      yes,
				Verbose:  verbose,
			}
			if err := mapExit(settingscmd.Set(cmd.Context(), d, opts)); err != nil {
				return err
			}
			if !jsonMode(cmd) {
				return nil
			}
			return emitData(cmd, resultdto.OperationSettingsSet, projectAt(cwd), resultdto.SettingsSetData{DryRun: dryRun})
		},
	}
	f := c.Flags()
	f.BoolVar(&dryRun, "dry-run", false, "show plan without modifying files")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation before applying")
	return withResult(c, resultdto.OperationSettingsSet)
}

// newSettingsEditCmd creates `tplater settings edit [group]`.
func newSettingsEditCmd() *cobra.Command {
	var (
		dryRun bool
		yes    bool
	)
	c := &cobra.Command{
		Use:   "edit [group]",
		Short: "Re-prompt one settings group interactively",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: working directory: %w", err)
			}
			opts := settingscmd.Options{
				StartDir: cwd,
				DryRun:   dryRun,
				Yes:      yes,
				Verbose:  verbose,
			}
			if len(args) == 1 {
				opts.Group = args[0]
			}
			return mapExit(settingscmd.Edit(cmd.Context(), d, opts))
		},
	}
	f := c.Flags()
	f.BoolVar(&dryRun, "dry-run", false, "show plan without modifying files")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation before applying")
	return c
}

// settingsDeps assembles settings command dependencies (manager, home, streams,
// questionnaire) and returns cleanup that closes the token store.
func settingsDeps(cmd *cobra.Command) (settingscmd.Deps, func(), error) {
	home, _, err := state.EnsureHome()
	if err != nil {
		return settingscmd.Deps{}, func() {}, err
	}
	mgr, st, err := newManager(cmd)
	if err != nil {
		return settingscmd.Deps{}, func() {}, err
	}
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	d := settingscmd.Deps{
		Manager:     mgr,
		Home:        home,
		Out:         humanOut(cmd),
		Err:         cmd.ErrOrStderr(),
		Palette:     ui.Default(),
		Prompter:    survey.HuhPrompter{In: cmd.InOrStdin(), Out: humanOut(cmd)},
		Interactive: interactive,
	}
	return d, func() { _ = st.Close() }, nil
}

// mapExit translates [update.ExitCodeError] (through settingscmd) into the
// exit-code registry: its code 2 ("conflicts remain") becomes exit 4
// (conflict) and code 1 ("markers found") exit 1 (finding); see
// docs/exit-codes.md.
func mapExit(err error) error {
	var ece *update.ExitCodeError
	if errors.As(err, &ece) {
		return &resultExitError{code: updateExit(ece.Code), err: ece.Err}
	}
	return err
}
