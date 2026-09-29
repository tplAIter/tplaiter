package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/contribute"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// contributeRunner — runner for glab/gh commands used by `tplater upgrade`. A
// package variable replaced with execx.RecordingRunner in tests (like repoRunner).
var contributeRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newUpgradeCmd)
}

// newUpgradeCmd creates `tplater upgrade`: the reverse flow, where improvements
// in the generated project are proposed to the template through an MR/PR.
func newUpgradeCmd() *cobra.Command {
	var (
		files []string
		title string
		draft bool
		patch bool
		yes   bool
	)

	c := &cobra.Command{
		Use:   "upgrade",
		Short: "Предложить доработки проекта в шаблон (MR/PR)",
		Long: "Сравнивает рабочее дерево проекта с чистым рендером зафиксированной версии шаблона " +
			"(эталон, как `tplater stats`) и предлагает изменённые файлы обратно в репозиторий шаблона " +
			"(). Кандидаты — изменённые файлы эталона (go.mod/go.sum исключены как шумные); " +
			"extra-файлы добавляются только явным --files <glob>. Выбранные файлы де-параметризуются " +
			"(slug/module/имя проекта → плейсхолдеры `{{ .Project.* }}`), кладутся в исходные `.tmpl` " +
			"дерева шаблона в новой ветке кеш-клона, после чего открывается MR (`glab`) / PR (`gh`) по " +
			"типу репозитория.\n\n" +
			"Условные блоки настроек обратно не восстанавливаются: файл условной вертикали помечается " +
			"комментарием TPLATER-REVIEW для ручной проверки мейнтейнером. Для репозиториев без " +
			"API-доступа (или обычного git) используйте --patch — вместо push+MR формируется серия " +
			"`git format-patch` в ./tplater-upgrade-<date>/. Прямых пушей в защищённые ветки не делается.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			home, _, err := state.EnsureHome()
			if err != nil {
				return err
			}

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: upgrade: определение рабочего каталога: %w", err)
			}

			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			var picker contribute.FilePicker
			if interactive {
				picker = contribute.HuhPicker{In: cmd.InOrStdin(), Out: cmd.OutOrStdout()}
			} else {
				picker = contribute.ScriptedPicker{} // non-interactive — all candidates.
			}

			_, err = contribute.Upgrade(cmd.Context(), contribute.Deps{
				Manager: mgr,
				Runner:  contributeRunner,
				Home:    home,
				Out:     cmd.OutOrStdout(),
				Err:     cmd.ErrOrStderr(),
				Palette: ui.Default(),
				Picker:  picker,
			}, contribute.Options{
				StartDir: cwd,
				Files:    files,
				Title:    title,
				Draft:    draft,
				Patch:    patch,
				Yes:      yes || !interactive,
			})
			return err
		},
	}

	f := c.Flags()
	f.StringArrayVar(&files, "files", nil, "glob extra-файлов для включения (повторяемый)")
	f.StringVar(&title, "title", "", "заголовок MR/PR")
	f.BoolVar(&draft, "draft", false, "открыть MR/PR черновиком")
	f.BoolVar(&patch, "patch", false, "сформировать git format-patch вместо push+MR")
	f.BoolVar(&yes, "yes", false, "не задавать вопросов (выбрать всех кандидатов)")
	return c
}
