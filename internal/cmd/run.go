package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// runRunner — Runner для исполнения команд манифеста. Вынесен в пакетную
// переменную по образцу authRunner (см. auth.go), чтобы тесты могли
// подставить свой Runner; по умолчанию — реальный execx.Exec{}, так как сама
// суть `tplater run` — реально исполнить команду проекта, а не подделать это.
var runRunner execx.Runner = execx.Exec{}

func init() {
	rootCmd.AddCommand(newRunCmd())
}

// newRunCmd создаёт команду `tplater run` .
func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run [name] [-- args...]",
		Short: "Показать команды проекта или исполнить одну из них",
		Long: "Без аргументов печатает список команд манифеста шаблона (commands) — " +
			"имя, описание и статус по when-условию текущих настроек проекта.\n\n" +
			"С именем команды исполняет её `run` через $SHELL -c в корне проекта: " +
			"`tplater run build -- --race` передаёт `--race` самой команде. " +
			"Сигналы INT/TERM, полученные tplater, пересылаются запущенному процессу; " +
			"код возврата команды становится кодом возврата tplater.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tpl, proj, root, err := loadRunContext()
			if err != nil {
				return err
			}
			values := settingsValues(proj.Settings)

			if len(args) == 0 {
				return listRunCommands(cmd, tpl.Commands, values)
			}
			return execRunCommand(cmd, tpl.Commands, values, root, args[0], args[1:])
		},
	}
}

// loadRunContext находит корень проекта от текущего рабочего каталога и
// разрешает манифест шаблона, к которому проект привязан (см.
// project.FindRoot/LoadManifestForProject).
func loadRunContext() (tpl *manifest.Template, proj *manifest.Project, root string, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cmd: run: определение рабочего каталога: %w", err)
	}
	home, err := state.Home()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cmd: run: определение домашнего каталога: %w", err)
	}

	root, proj, err = project.FindRoot(cwd)
	if err != nil {
		return nil, nil, "", err
	}
	tpl, _, err = project.LoadManifestForProject(root, proj, home)
	if err != nil {
		return nil, nil, "", err
	}
	return tpl, proj, root, nil
}

// settingsValues приводит manifest.Project.Settings (карта как она разобрана
// yaml.v3 из .tplaiter/project.yaml) к [settings.Values] для [settings.Eval].
// Значения переносятся как есть — scalar-типы (string/bool/int), которые
// yaml.v3 уже раскладывает в родные Go-типы при разборе в map[string]any, не
// трогаются. Единственная нормализация: multiselect-группы yaml.v3 отдаёт как
// []any (список интерфейсов), а не []string, которого ждёт [settings.Eval] —
// без этого шага when-условия на multiselect-группы (`brokers=kafka`) были бы
// всегда false. Не строгая типизация ([settings.ParseSet]/[settings.LoadAnswersFile]
// его делают со сверкой опций манифеста) — просто устранение артефакта
// разбора YAML.
func settingsValues(raw map[string]any) settings.Values {
	out := make(settings.Values, len(raw))
	for k, v := range raw {
		if list, ok := v.([]any); ok {
			strs := make([]string, 0, len(list))
			for _, item := range list {
				if s, ok := item.(string); ok {
					strs = append(strs, s)
				}
			}
			out[k] = strs
			continue
		}
		out[k] = v
	}
	return out
}

// evalWhen разбирает и вычисляет строку when-условия команды манифеста.
// Пустая строка when здесь не встречается — это ответственность вызывающего
// (означает "условий нет, всегда доступна").
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}

// listRunCommands печатает таблицу команд манифеста: NAME/DESCRIPTION/WHEN.
// Команды с невыполненным (или неразрешимым — например, ссылка на
// неизвестную группу) when показываются приглушённо палитрой с пометкой
// "недоступно" — по образцу [statusCell] в doctor.go, цвет только в
// последней колонке, чтобы не сломать выравнивание таблицы ANSI-кодами.
func listRunCommands(cmd *cobra.Command, commands map[string]manifest.Command, values settings.Values) error {
	out := cmd.OutOrStdout()
	if len(commands) == 0 {
		fmt.Fprintln(out, "манифест шаблона не объявляет команд (commands)")
		return nil
	}

	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	pal := ui.Default()
	table := ui.NewTable("NAME", "DESCRIPTION", "WHEN")
	for _, name := range names {
		c := commands[name]
		table.AddRow(name, c.Description, whenCell(pal, c.When, values))
	}
	fmt.Fprintln(out, table.RenderStyled(pal))
	return nil
}

// whenCell формирует последнюю колонку списка команд: пусто, если у команды
// нет when; сам условие как есть, если оно выполнено; приглушённая пометка
// "недоступно", если нет (в том числе если условие ссылается на неизвестную
// группу — такую команду тоже исполнить нельзя).
func whenCell(pal ui.Palette, when string, values settings.Values) string {
	if when == "" {
		return ""
	}
	ok, err := evalWhen(when, values)
	if err != nil || !ok {
		return ui.StatusIcon(pal, ui.StatusWarn) + " " + pal.Muted(when+" — недоступно при текущих настройках")
	}
	return ui.StatusIcon(pal, ui.StatusOK) + " " + when
}

// execRunCommand исполняет run именованной команды манифеста через
// $SHELL -c в корне проекта root, передавая extraArgs команде и пересылая ей
// сигналы INT/TERM. Код возврата команды пробрасывается наружу через
// [ExitError] — main() транслирует его в exit-код процесса.
//
// Способ передачи extraArgs: `$SHELL -c '<run> "$@"' sh arg1 arg2 ...` —
// классический POSIX-приём (см. `man sh`: -c с дополнительными операндами
// после script задаёт $0/$1/.../"$@"). Аргументы уходят в exec как отдельные
// элементы argv, а не конкатенируются в текст скрипта — поэтому кавычки/
// спецсимволы в args (например, `--race`, пути с пробелами) не нужно
// экранировать самим и невозможно случайно сломать синтаксис скрипта
// инъекцией. Литерал "sh" — это просто метка $0 подпроцесса (не влияет на
// исполнение), нужна только затем, чтобы "$@" начинался с $1, а не поглощал
// первый реальный аргумент под видом $0; принимается любым POSIX-совместимым
// shell (bash/zsh/dash/ash), включая /bin/sh-фоллбек.
func execRunCommand(
	cmd *cobra.Command,
	commands map[string]manifest.Command,
	values settings.Values,
	root, name string,
	extraArgs []string,
) error {
	c, ok := commands[name]
	if !ok {
		return fmt.Errorf("cmd: run: неизвестная команда %q — доступные: %s", name, availableNames(commands))
	}

	if c.When != "" {
		ok, err := evalWhen(c.When, values)
		if err != nil || !ok {
			return fmt.Errorf("команда недоступна при текущих настройках: %s", c.When)
		}
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	script := c.Run + ` "$@"`
	shellArgs := append([]string{"-c", script, "sh"}, extraArgs...)

	// Сигналы, полученные самим tplater (Ctrl+C и т.п.), пересылаются
	// исполняемой команде — см. execx.Options.Signals и
	// execx.runWithSignalForwarding (запускает $SHELL в отдельной группе
	// процессов, чтобы сигнал доставался и реальной программе, не только
	// самой оболочке).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	_, err := runRunner.Run(cmd.Context(), shell, shellArgs, execx.Options{
		Dir:     root,
		Stdin:   cmd.InOrStdin(),
		Stdout:  cmd.OutOrStdout(),
		Stderr:  cmd.ErrOrStderr(),
		Signals: sigCh,
	})

	var exitErr *execx.ExitError
	if errors.As(err, &exitErr) {
		return &ExitError{Code: exitErr.ExitCode, Err: err}
	}
	return err
}

// availableNames возвращает отсортированный список имён команд манифеста —
// подсказка в сообщении об ошибке "неизвестная команда".
func availableNames(commands map[string]manifest.Command) string {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "(нет команд в манифесте)"
	}
	return strings.Join(names, ", ")
}
