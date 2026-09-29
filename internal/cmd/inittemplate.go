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
		Short: "Создать репозиторий шаблона со всем инструментарием",
		Long: "Генерирует пустой tplaiter-совместимый репозиторий шаблона: " +
			"скелет template.manifest.yaml с примерными группами настроек, дерево files/ с " +
			"рабочим минимальным примером, генератор, ai-config, плейбук окружения, NOTES, " +
			"README мейнтейнера и GitHub Actions workflow с проверкой lint-template.\n\n" +
			"--multi добавляет repo.manifest.yaml и кладёт шаблон в подкаталог <name>/. " +
			"По умолчанию делает git init и первый коммит (--no-git отключает).",
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
	f.StringVar(&dir, "dir", "", "целевой каталог репозитория (по умолчанию ./<name>)")
	f.BoolVar(&multi, "multi", false, "multi-репозиторий (repo.manifest.yaml + шаблон в подкаталоге <name>/)")
	f.BoolVar(&noGit, "no-git", false, "не выполнять git init и первый коммит")
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
		Short: "Селфтест репозитория шаблона по угловым комбинациям настроек",
		Long: "Находит манифест(ы) репозитория шаблона (single в корне или multi через " +
			"repo.manifest.yaml/скан), валидирует каждый шаблон и прогоняет пробный рендер " +
			"по всем «угловым» комбинациям настроек (): defaults, каждая select/" +
			"multiselect-опция, все toggle разом (all-on) и полный max. Для каждой комбо " +
			"проверяет рендер, NOTES, парс генераторов, ai-config и YAML плейбуков окружения.\n\n" +
			"Печатает таблицу (шаблон × комбо × статус); возвращает код 1 при провале.",
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
				return &ExitError{Code: 1, Err: errors.New("lint-template: обнаружены провалы")}
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&path, "path", ".", "корень репозитория шаблона")
	f.StringVar(&combo, "combo", "", "фильтр по имени комбинации (точное совпадение)")
	return c
}
