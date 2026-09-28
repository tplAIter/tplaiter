package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
	"github.com/tplAIter/tplaiter/internal/update"
)

func init() {
	rootCmd.AddCommand(newSettingsCmd())
}

// newSettingsCmd creates `tplater settings`: viewing and changing project
// settings with the same 3-way mechanism as `tplater update`, but on the
// current template version.
func newSettingsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "settings",
		Short: "Просмотр и изменение настроек проекта",
		Long: "Управляет настройками сгенерированного проекта. " +
			"`list` показывает текущие значения; `set group=value` меняет их той же " +
			"3-way-механикой, что и update (смена select-значения удаляет старую " +
			"вертикаль файлов и добавляет новую, локальные правки сохраняются или дают " +
			"конфликт-маркеры); `edit <group>` переопрашивает одну группу интерактивно. " +
			"Версия шаблона и хуки не затрагиваются — только рендер с новыми значениями.",
	}
	c.AddCommand(newSettingsListCmd())
	c.AddCommand(newSettingsSetCmd())
	c.AddCommand(newSettingsEditCmd())
	return c
}

// newSettingsListCmd creates `tplater settings list`.
func newSettingsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Показать текущие значения настроек проекта",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: рабочий каталог: %w", err)
			}
			return settingscmd.List(d, settingscmd.Options{StartDir: cwd})
		},
	}
}

// newSettingsSetCmd creates `tplater settings set group=value [...]`.
func newSettingsSetCmd() *cobra.Command {
	var (
		dryRun bool
		yes    bool
	)
	c := &cobra.Command{
		Use:   "set group=value [group2=value2 ...]",
		Short: "Изменить настройки проекта (3-way merge на текущей версии)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: рабочий каталог: %w", err)
			}
			opts := settingscmd.Options{
				StartDir: cwd,
				Pairs:    args,
				DryRun:   dryRun,
				Yes:      yes,
				Verbose:  verbose,
			}
			return mapExit(settingscmd.Set(cmd.Context(), d, opts))
		},
	}
	f := c.Flags()
	f.BoolVar(&dryRun, "dry-run", false, "показать план без изменения файлов")
	f.BoolVar(&yes, "yes", false, "не запрашивать подтверждение перед применением")
	return c
}

// newSettingsEditCmd creates `tplater settings edit [group]`.
func newSettingsEditCmd() *cobra.Command {
	var (
		dryRun bool
		yes    bool
	)
	c := &cobra.Command{
		Use:   "edit [group]",
		Short: "Переопросить одну группу настроек интерактивно",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, cleanup, err := settingsDeps(cmd)
			if err != nil {
				return err
			}
			defer cleanup()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: settings: рабочий каталог: %w", err)
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
	f.BoolVar(&dryRun, "dry-run", false, "показать план без изменения файлов")
	f.BoolVar(&yes, "yes", false, "не запрашивать подтверждение перед применением")
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
		Out:         cmd.OutOrStdout(),
		Err:         cmd.ErrOrStderr(),
		Palette:     ui.Default(),
		Prompter:    survey.HuhPrompter{In: cmd.InOrStdin(), Out: cmd.OutOrStdout()},
		Interactive: interactive,
	}
	return d, func() { _ = st.Close() }, nil
}

// mapExit translates [update.ExitCodeError] (through settingscmd) into
// [ExitError] for the process exit code (2 means remaining conflict markers).
func mapExit(err error) error {
	var ece *update.ExitCodeError
	if errors.As(err, &ece) {
		return &ExitError{Code: ece.Code, Err: ece.Err}
	}
	return err
}
