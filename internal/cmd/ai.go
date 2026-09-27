package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/aiconfig"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// aiTargetsFlag — флаг `--targets` команды `tplater ai gen` (пусто → все
// таргеты config.json источника, см. [aiconfig.RenderOptions.Targets]).
var aiTargetsFlag []string

func init() {
	rootCmd.AddCommand(newAICmd())
}

// newAICmd создаёт команду `tplater ai`: генерация/список/
// валидация AI-конфигурации проекта (CLAUDE.md/.cursor/**/AGENTS.md/GEMINI.md)
// из каталога-копии .tplaiter/ai-config (контракт с /).
func newAICmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ai",
		Short: "AI-конфигурация проекта (CLAUDE.md, .cursor/**, AGENTS.md, GEMINI.md)",
		Long: "Работает с каталогом-копией ai-config, который `tplater new` кладёт в проект " +
			"как .tplaiter/ai-config (). Модули гейтятся условием `when` (§3.2) на " +
			"текущих настройках проекта — модуль без when активен всегда.",
	}
	c.AddCommand(newAIGenCmd(), newAIListCmd(), newAIValidateCmd())
	return c
}

// loadAIContext находит корень проекта, разрешает манифест шаблона и
// открывает источник .tplaiter/ai-config. Понятная ошибка, если каталог
// отсутствует (шаблон не подключает aiConfig либо  ещё не скопировал его).
func loadAIContext() (tpl *manifest.Template, values settings.Values, root string, src *aiconfig.Source, err error) {
	tpl, proj, root, err := loadRunContext()
	if err != nil {
		return nil, nil, "", nil, err
	}

	dir := filepath.Join(root, aiconfig.AIConfigRelPath)
	if _, statErr := os.Stat(dir); statErr != nil {
		return nil, nil, "", nil, fmt.Errorf(
			"ai: каталог %s не найден — шаблон не подключает aiConfig либо проект создан без него", aiconfig.AIConfigRelPath,
		)
	}

	src, err = aiconfig.Load(dir)
	if err != nil {
		return nil, nil, "", nil, err
	}
	return tpl, settingsValues(proj.Settings), root, src, nil
}

// newAIGenCmd создаёт `tplater ai gen`.
func newAIGenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "gen",
		Short: "Сгенерировать AI-артефакты в корень проекта",
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
			return printAIResult(cmd, res)
		},
	}
	c.Flags().StringSliceVar(&aiTargetsFlag, "targets", nil,
		"ограничить генерацию списком таргетов (по умолчанию — все config.targets источника)")
	return c
}

// printAIResult печатает записанные и пропущенные (защищённые 99-*) файлы.
func printAIResult(cmd *cobra.Command, res *aiconfig.Result) error {
	out := cmd.OutOrStdout()
	for _, f := range res.Written {
		fmt.Fprintf(out, "записан %s\n", f)
	}
	for _, f := range res.SkippedProtected {
		fmt.Fprintf(out, "пропущен %s (проектное дополнение 99-*)\n", f)
	}
	return nil
}

// newAIListCmd создаёт `tplater ai list`.
func newAIListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Список модулей ai-config (id/title/activation/when/available)",
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

// printAIList печатает таблицу ID/TITLE/ACTIVATION/WHEN.
func printAIList(cmd *cobra.Command, src *aiconfig.Source, values settings.Values) error {
	out := cmd.OutOrStdout()
	if len(src.Modules) == 0 {
		fmt.Fprintln(out, "источник ai-config не объявляет модулей")
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
			// нет when — модуль активен всегда, колонка пустая.
		case activeIDs[m.ID]:
			when = ui.StatusIcon(pal, ui.StatusOK) + " " + when
		default:
			when = ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted(when+" — недоступно при текущих настройках")
		}
		table.AddRow(m.ID, m.Title, m.Activation, when)
	}
	fmt.Fprintln(out, table.RenderStyled(pal))
	return nil
}

// newAIValidateCmd создаёт `tplater ai validate`. Манифест шаблона резолвится
// той же цепочкой источников, что и `tplater run`/`gen` ([loadRunContext] →
// [project.LoadManifestForProject]): сейчас репо-кеш всегда недоступен, поэтому
// фактически используется снимок .tplaiter/manifest.snapshot.yaml — отсутствие
// снимка даёт понятную ошибку ([project.ErrNoManifest]) без отдельного кода.
func newAIValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Проверить источник ai-config против манифеста шаблона проекта",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tpl, _, _, src, err := loadAIContext()
			if err != nil {
				return err
			}
			if err := src.Validate(tpl); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ai-config валиден")
			return nil
		},
	}
}
