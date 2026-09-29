package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/envsetup"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// envRunner — runner for ansible-playbook/brew (environment setup and dependency
// installation). A package variable like runRunner/repoRunner; tests substitute
// execx.RecordingRunner, while the default uses real os/exec.
var envRunner execx.Runner = execx.Exec{}

// envAutoYes — `--yes` for `tplater env setup`: confirms ansible installation
// without an interactive prompt (SPEC-03 §4). A full huh-confirm belongs to
// the questionnaire task (C2/tp-U1); this is the sole consent source for
// non-interactive scenarios (CI, scripts).
var envAutoYes bool

func init() {
	registerCommand(newEnvCmd)
}

// newEnvCmd creates `tplater env` (SPEC-03 §4): the single entry point for
// environment ansible playbooks shipped with the template.
func newEnvCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "env",
		Short: "Настройка окружения проекта через ansible-плейбуки шаблона",
		Long: "Шаблон декларирует environment.playbooks (SPEC-01 §2) — ansible-плейбуки " +
			"настройки окружения (инфраструктура, зависимости и т.п.). tplater — единая точка " +
			"их запуска: устанавливает ansible при необходимости и исполняет плейбук с " +
			"extra-vars из настроек и идентификации текущего проекта.\n\n" +
			"См. specs/SPEC-03-scaffolding.md §4.",
	}
	c.AddCommand(newEnvListCmd(), newEnvSetupCmd())
	return c
}

// newEnvListCmd creates `tplater env list`.
func newEnvListCmd() *cobra.Command {
	return &cobra.Command{
		Use:         "list",
		Annotations: prerunAnnotations(prerunReadonly),
		Short:       "Показать плейбуки окружения манифеста шаблона",
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, proj, _, err := loadRunContext()
			if err != nil {
				return err
			}
			return renderPlaybookList(cmd, tpl, settingsValues(proj.Settings))
		},
	}
}

// newEnvSetupCmd creates `tplater env setup [name]` (name=setup by default,
// SPEC-03 §4).
func newEnvSetupCmd() *cobra.Command {
	c := &cobra.Command{
		Use:         "setup [name]",
		Annotations: prerunAnnotations(prerunLegacyAction),
		Short:       "Запустить плейбук окружения (по умолчанию \"setup\")",
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Cobra rejects this before root hooks; retain the same guard for a
			// directly constructed setup command.
			return actionUnavailable()
			/*
				name := "setup"
				if len(args) == 1 {
					name = args[0]
				}

				tpl, proj, root, err := loadRunContext()
				if err != nil {
					return err
				}

				pb, err := findPlaybook(tpl.Environment.Playbooks, name)
				if err != nil {
					return err
				}

				runner := envsetup.NewRunner(envRunner, cmd.OutOrStdout(), ui.Default())
				runErr := runner.RunPlaybook(cmd.Context(), envsetup.Options{
					TemplateDir: filepath.Join(root, envsetup.EnvironmentRelPath),
					ProjectRoot: root,
					Playbook:    pb,
					Values:      settingsValues(proj.Settings),
					Project:     proj.Project,
					AutoYes:     envAutoYes,
				})

				var exitErr *execx.ExitError
				if errors.As(runErr, &exitErr) {
					return &ExitError{Code: exitErr.ExitCode, Err: runErr}
				}
				return runErr
			*/
		},
	}
	c.Flags().BoolVar(&envAutoYes, "yes", false, "подтвердить установку ansible без интерактивного вопроса")
	return c
}

// findPlaybook finds the playbook named name among the manifest playbooks.
func findPlaybook(playbooks []manifest.Playbook, name string) (manifest.Playbook, error) {
	for _, pb := range playbooks {
		if pb.Name == name {
			return pb, nil
		}
	}
	return manifest.Playbook{}, fmt.Errorf(
		"cmd: env setup: неизвестный плейбук %q — доступные: %s", name, availablePlaybookNames(playbooks),
	)
}

// availablePlaybookNames returns a sorted list of playbook names for the
// "unknown playbook" error hint.
func availablePlaybookNames(playbooks []manifest.Playbook) string {
	if len(playbooks) == 0 {
		return "(манифест не объявляет плейбуков окружения — environment.playbooks)"
	}
	names := make([]string, 0, len(playbooks))
	for _, pb := range playbooks {
		names = append(names, pb.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// renderPlaybookList prints the manifest environment playbooks as a
// NAME/DESCRIPTION/AVAILABLE table (following listRunCommands in run.go).
func renderPlaybookList(cmd *cobra.Command, tpl *manifest.Template, values settings.Values) error {
	out := cmd.OutOrStdout()
	infos := envsetup.ListPlaybooks(tpl, values)
	if len(infos) == 0 {
		fmt.Fprintln(out, "манифест шаблона не объявляет плейбуков окружения (environment.playbooks)")
		return nil
	}

	pal := ui.Default()
	table := ui.NewTable("NAME", "DESCRIPTION", "AVAILABLE")
	for _, info := range infos {
		table.AddRow(info.Name, info.Description, availableCell(pal, info))
	}
	fmt.Fprintln(out, table.RenderStyled(pal))
	return nil
}

// availableCell builds the last column of the playbook list: "yes" (success),
// or a dimmed "no" with the reason (a when condition that is unmet or cannot
// be resolved), following whenCell/statusCell in run.go/doctor.go.
func availableCell(pal ui.Palette, info envsetup.PlaybookInfo) string {
	if info.Available {
		return ui.StatusIcon(pal, ui.StatusOK) + " да"
	}
	if info.WhenStr == "" {
		return ui.StatusIcon(pal, ui.StatusFail) + " нет"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted("нет — недоступно при текущих настройках ("+info.WhenStr+")")
}
