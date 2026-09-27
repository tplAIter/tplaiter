package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// firstRunSkip — верхнеуровневые команды, которые не должны шуметь
// приветствием first-run: пользователь спрашивает справку/версию
// — молчим про ~/.tplaiter, даже если это первый запуск на машине.
var firstRunSkip = map[string]bool{
	"help":       true,
	"version":    true,
	"completion": true,
}

// firstRunPreRun — PersistentPreRunE корневой команды. Если домашний каталог
// tplaiter ещё не существовал и вызываемая команда не входит в firstRunSkip,
// создаёт его скелет ([state.EnsureHome]) и печатает короткое приветствие в
// stderr. Ошибка EnsureHome прерывает выполнение — без
// ~/.tplaiter работоспособны только help/version, остальным командам он нужен.
func firstRunPreRun(cmd *cobra.Command, _ []string) error {
	if firstRunSkip[topLevelCommand(cmd).Name()] {
		return nil
	}

	_, created, err := state.EnsureHome()
	if err != nil {
		return fmt.Errorf("cmd: first-run: %w", err)
	}
	if created {
		printWelcome(cmd)
	}
	return nil
}

// topLevelCommand возвращает верхнеуровневую подкоманду (прямого потомка
// rootCmd) на пути к cmd — например, "completion" для `tplaiter completion
// bash`, "version" для `tplaiter version`. Используется вместо cmd.Name(),
// потому что first-run должен молчать для ЛЮБОЙ команды внутри "completion",
// а не только для самой команды completion.
func topLevelCommand(cmd *cobra.Command) *cobra.Command {
	c := cmd
	for c.HasParent() && c.Parent().HasParent() {
		c = c.Parent()
	}
	return c
}

// printWelcome печатает приветствие первого запуска: как добавить репозиторий
// шаблонов и где искать документацию ( ровно три строки).
func printWelcome(cmd *cobra.Command) {
	p := ui.Default()
	out := cmd.ErrOrStderr()
	fmt.Fprintln(out, p.Muted("tplaiter: создан каталог ~/.tplaiter — это первый запуск на этой машине."))
	fmt.Fprintln(out, p.Muted("Добавьте репозиторий шаблонов:  tplaiter repo add <alias> <url>"))
	fmt.Fprintln(out, p.Muted("Документация: README.md и docs/ в репозитории tplaiter."))
}
