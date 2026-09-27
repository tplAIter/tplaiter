package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/projectsync"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func init() {
	rootCmd.AddCommand(newProjectsCmd())
}

// projectSyncSkip — top-level команды, для которых синхронизация реестра
// проектов не имеет смысла: справка/версия/автодополнение — те
// же причины, что и у [firstRunSkip]/[suggestSkip] (см. firstrun.go,
// selfupgrade.go), плюс init-shell (тонкий алиас completion).
var projectSyncSkip = map[string]bool{
	"help":       true,
	"version":    true,
	"completion": true,
	"init-shell": true,
}

// projectSyncPreRun — третий (и последний) элемент цепочки
// PersistentPreRunE корневой команды (см. [rootPreRun] в root.go,
// §1): если рабочий каталог находится внутри проекта tplater, приводит его
// запись в ~/.tplaiter/projects.yaml в соответствие с фактическим состоянием
// — [projectsync.SyncCurrent] делает всю работу.
//
// В отличие от firstRunPreRun, ошибка НЕ прерывает выполнение вызывающей
// команды: реестр — удобство навигации, а не источник истины.
// При сбое (недоступен home, занят лок, побитый .tplaiter/project.yaml)
// диагностика печатается только при --verbose; обычный прогон остаётся
// молчаливым.
func projectSyncPreRun(cmd *cobra.Command, _ []string) {
	if projectSyncSkip[topLevelCommand(cmd).Name()] {
		return
	}

	home, err := state.Home()
	if err != nil {
		logProjectSyncErr(cmd, err)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		logProjectSyncErr(cmd, err)
		return
	}
	if err := projectsync.SyncCurrent(home, cwd, time.Now()); err != nil {
		logProjectSyncErr(cmd, err)
	}
}

func logProjectSyncErr(cmd *cobra.Command, err error) {
	if !verbose {
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "tplater: синхронизация реестра проектов: %v\n", err)
}

// newProjectsCmd создаёт команду `tplater projects`: просмотр и
// уборка локального реестра ~/.tplaiter/projects.yaml.
func newProjectsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "projects",
		Short: "Реестр проектов, сгенерированных из шаблонов на этой машине",
		Long: "Реестр ~/.tplaiter/projects.yaml — удобство навигации, а не источник истины " +
			"(): источник истины — .tplaiter/ внутри самого проекта. Реестр " +
			"актуализируется автоматически каждой командой tplater, запущенной внутри " +
			"проекта: переезд каталога отслеживается по стабильному id из " +
			".tplaiter/project.yaml, проект без записи (клонирован коллегой) " +
			"регистрируется по факту, а расхождение baselineSHA (проект обновляли на " +
			"другой машине) обновляется по факту.",
	}
	c.AddCommand(newProjectsListCmd(), newProjectsPruneCmd())
	return c
}

func newProjectsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Список проектов реестра (PATH/TEMPLATE/LAST SEEN/STATUS)",
		Long: "Столбец STATUS:\n" +
			"  ok      — каталог по PATH существует и .tplaiter/project.yaml в нём читается.\n" +
			"  missing — каталог удалён или маркер проекта пропал; запись чистится\n" +
			"            командой `tplater projects prune`.\n\n" +
			"Отдельного статуса «переехал» нет: переезд каталога (тот же id проекта, " +
			"другой путь) обнаруживается и правится автоматически при первом же запуске " +
			"tplater внутри нового пути — синхронизация реестра встроена в " +
			"PersistentPreRunE каждой команды (см. root.go), так что list всегда видит " +
			"уже актуальный PATH, а не устаревший.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := state.Home()
			if err != nil {
				return err
			}
			projects, err := state.LoadProjects(home)
			if err != nil {
				return err
			}

			pal := ui.Default()
			t := ui.NewTable("PATH", "TEMPLATE", "LAST SEEN", "STATUS")
			for _, ref := range projects.Items {
				t.AddRow(ref.Path, formatTemplateSelection(ref.Template), dashTime(ref.LastSeenAt), statusCellProjects(pal, ref))
			}
			fmt.Fprintln(cmd.OutOrStdout(), t.RenderStyled(pal))
			return nil
		},
	}
}

func newProjectsPruneCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "prune",
		Short: "Удалить из реестра записи со статусом missing",
		Long: "Убирает записи, для которых каталог по PATH не существует или в нём пропал " +
			".tplaiter/project.yaml (тот же критерий, что STATUS=missing в `projects list`). " +
			"Перед удалением печатает список записей-кандидатов; без --yes запрашивает " +
			"подтверждение интерактивно (huh), в неинтерактивном режиме требует --yes явно.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := state.Home()
			if err != nil {
				return err
			}
			return state.WithLock(home, func() error {
				projects, err := state.LoadProjects(home)
				if err != nil {
					return err
				}

				stale := missingRefs(projects.Items)
				if len(stale) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "нет записей со статусом missing — реестр чист.")
					return nil
				}

				out := cmd.OutOrStdout()
				fmt.Fprintln(out, "будут удалены из реестра (STATUS=missing):")
				for _, ref := range stale {
					fmt.Fprintf(out, "  %s  (%s)\n", ref.Path, formatTemplateSelection(ref.Template))
				}

				if !yes {
					confirmed, err := confirmPrune(cmd, len(stale))
					if err != nil {
						return err
					}
					if !confirmed {
						fmt.Fprintln(out, "отменено, реестр не изменён.")
						return nil
					}
				}

				removed := projects.Prune(func(path string) bool {
					_, statErr := os.Stat(filepath.Join(path, project.MarkerRelPath))
					return statErr == nil
				})
				if err := state.SaveProjects(home, projects); err != nil {
					return err
				}
				fmt.Fprintf(out, "удалено записей: %d\n", len(removed))
				return nil
			})
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "не спрашивать подтверждения")
	return c
}

// confirmPrune запрашивает подтверждение удаления n записей: интерактивно
// через huh, если stdin — терминал; иначе требует явного --yes, а не
// предполагает согласие по умолчанию (удаление из реестра — операция без
// отмены).
func confirmPrune(cmd *cobra.Command, n int) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("cmd: projects prune: неинтерактивный режим — подтвердите флагом --yes")
	}
	var ok bool
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(fmt.Sprintf("Удалить %d запис(ь/и) из реестра?", n)).
			Affirmative("Да").Negative("Нет").Value(&ok),
	))
	form = form.WithInput(cmd.InOrStdin()).WithOutput(cmd.OutOrStdout())
	if err := form.Run(); err != nil {
		return false, err
	}
	return ok, nil
}

// missingRefs возвращает подмножество items со статусом missing — тот же
// критерий, что [state.Projects.Prune] использует для реального удаления.
func missingRefs(items []state.ProjectRef) []state.ProjectRef {
	var out []state.ProjectRef
	for _, ref := range items {
		if !projectRefExists(ref) {
			out = append(out, ref)
		}
	}
	return out
}

// projectRefExists проверяет STATUS=ok для одной записи реестра: каталог по
// ref.Path существует и в нём читается .tplaiter/project.yaml. Единственная
// проверка os.Stat маркера покрывает оба случая missing (удалён каталог
// целиком или только маркер внутри него), см. Long команды `projects list`.
func projectRefExists(ref state.ProjectRef) bool {
	_, err := os.Stat(filepath.Join(ref.Path, project.MarkerRelPath))
	return err == nil
}

func statusCellProjects(pal ui.Palette, ref state.ProjectRef) string {
	if projectRefExists(ref) {
		return ui.StatusIcon(pal, ui.StatusOK) + " ok"
	}
	return ui.StatusIcon(pal, ui.StatusWarn) + " missing"
}

func formatTemplateSelection(t state.TemplateSelection) string {
	return fmt.Sprintf("%s/%s@%s", t.Repo, t.Name, t.Version)
}
