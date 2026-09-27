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

// envRunner — Runner для ansible-playbook/brew (envsetup, деп-установка).
// Пакетная переменная по образцу runRunner/repoRunner — тесты подставляют
// execx.RecordingRunner, по умолчанию реальный os/exec.
var envRunner execx.Runner = execx.Exec{}

// envAutoYes — `--yes` команды `tplater env setup`: подтверждает установку
// ansible без интерактивного вопроса (SPEC-03 §4). Полноценный huh-confirm —
// задача опросника (C2/tp-U1); здесь единственный источник согласия для
// неинтерактивных сценариев (CI, скрипты).
var envAutoYes bool

func init() {
	rootCmd.AddCommand(newEnvCmd())
}

// newEnvCmd создаёт команду `tplater env` (SPEC-03 §4): единая точка запуска
// ansible-плейбуков окружения, которые везёт с собой шаблон.
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

// newEnvListCmd создаёт `tplater env list`.
func newEnvListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Показать плейбуки окружения манифеста шаблона",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, proj, _, err := loadRunContext()
			if err != nil {
				return err
			}
			return renderPlaybookList(cmd, tpl, settingsValues(proj.Settings))
		},
	}
}

// newEnvSetupCmd создаёт `tplater env setup [name]` (по умолчанию name=setup,
// SPEC-03 §4).
func newEnvSetupCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "setup [name]",
		Short: "Запустить плейбук окружения (по умолчанию \"setup\")",
		Args:  cobra.MaximumNArgs(1),
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

// findPlaybook ищет плейбук с именем name среди playbooks манифеста.
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

// availablePlaybookNames возвращает отсортированный список имён плейбуков —
// подсказка в сообщении об ошибке "неизвестный плейбук".
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

// renderPlaybookList печатает таблицу NAME/DESCRIPTION/AVAILABLE плейбуков
// окружения манифеста (по образцу listRunCommands в run.go).
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

// availableCell формирует последнюю колонку списка плейбуков: "да" (успех),
// либо приглушённое "нет" с причиной (when, который не выполнен либо
// неразрешим) — по образцу whenCell/statusCell в run.go/doctor.go.
func availableCell(pal ui.Palette, info envsetup.PlaybookInfo) string {
	if info.Available {
		return ui.StatusIcon(pal, ui.StatusOK) + " да"
	}
	if info.WhenStr == "" {
		return ui.StatusIcon(pal, ui.StatusFail) + " нет"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted("нет — недоступно при текущих настройках ("+info.WhenStr+")")
}
