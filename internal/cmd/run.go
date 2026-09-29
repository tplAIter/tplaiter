package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// runRunner — runner for executing manifest commands. It is a package variable
// like authRunner (see auth.go), allowing tests to substitute a Runner; the
// default is real execx.Exec{}, since `tplater run` must execute the project
// command for real.
var runRunner execx.Runner = execx.Exec{}

func init() {
	registerCommand(newRunCmd)
}

// newRunCmd creates `tplater run` (SPEC-01 §5, SPEC-04 §4).
func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:         "run [name] [-- args...]",
		Annotations: prerunAnnotations(prerunLegacyAction, prerunReadonly),
		Short:       "Показать команды проекта или исполнить одну из них",
		Long: "Без аргументов печатает список команд манифеста шаблона (commands, SPEC-01 §5) — " +
			"имя, описание и статус по when-условию текущих настроек проекта.\n\n" +
			"С именем команды исполняет её `run` через $SHELL -c в корне проекта: " +
			"`tplater run build -- --race` передаёт `--race` самой команде. " +
			"Сигналы INT/TERM, полученные tplater, пересылаются запущенному процессу; " +
			"код возврата команды становится кодом возврата tplater.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The composed root rejects this before its hooks.  Keep the same
			// ordering when callers construct newRunCmd directly: a named action
			// must not discover cwd, HOME, or a manifest before fixed material.
			if len(args) != 0 {
				return actionUnavailable()
			}
			tpl, proj, _, err := loadRunContext()
			if err != nil {
				return err
			}
			values := settingsValues(proj.Settings)

			return listRunCommands(cmd, tpl.Commands, values)
		},
	}
}

// loadRunContext finds the project root from the current working directory and
// resolves the manifest of the template to which the project is linked (see
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

// settingsValues converts manifest.Project.Settings (the map decoded by yaml.v3
// from .tplaiter/project.yaml) to [settings.Values] for [settings.Eval]. Scalar
// values (string/bool/int) are kept as decoded Go types. The only normalization
// is for multiselect groups: yaml.v3 returns []any rather than the []string
// expected by [settings.Eval]; without it, when conditions on multiselect
// groups (`brokers=kafka`) would always be false. This is not strict typing
// ([settings.ParseSet]/[settings.LoadAnswersFile] validate against manifest
// options), only removal of a YAML decoding artifact.
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

// evalWhen parses and evaluates a manifest command's when condition string.
// An empty when is not passed here; the caller treats it as always available.
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}

// listRunCommands prints the manifest command table: NAME/DESCRIPTION/WHEN.
// Commands with unmet or unresolvable when conditions (for example, a
// reference to an unknown group) are dimmed and marked "unavailable", like
// [statusCell] in doctor.go. Color is used only in the last column so ANSI
// codes do not break table alignment.
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

// whenCell builds the last command-list column: empty when the command has no
// when; the condition itself when it is true; or a dimmed "unavailable" mark
// when false, including when it references an unknown group.
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

// execRunCommand executes the named manifest command through $SHELL -c in
// project root, passing extraArgs and forwarding INT/TERM signals. The command
// exit code is returned through [ExitError], which main() converts to a process
// exit code.
//
// extraArgs are passed as `$SHELL -c '<run> "$@"' sh arg1 arg2 ...`, the
// classic POSIX mechanism (see `man sh`: operands after the script set
// $0/$1/.../"$@"). Arguments remain separate exec argv elements rather than
// being concatenated into the script, so quoting and special characters in
// args (such as `--race` or paths with spaces) need no escaping and cannot
// inject broken script syntax. The literal "sh" is only the subprocess $0
// label, ensuring "$@" starts at $1; any POSIX shell (bash/zsh/dash/ash),
// including the /bin/sh fallback, accepts it.
func execRunCommand(
	cmd *cobra.Command,
	commands map[string]manifest.Command,
	values settings.Values,
	root, name string,
	extraArgs []string,
) error {
	// Direct package callers receive the same denial as the Cobra ingress.
	// Do this before examining the manifest command or process environment.
	return actionUnavailable()
	/*
		c, ok := commands[name]
		if !ok {
			return fmt.Errorf("cmd: run: unknown command %q — available: %s", name, availableNames(commands))
		}

		if c.When != "" {
			ok, err := evalWhen(c.When, values)
			if err != nil || !ok {
				return fmt.Errorf("command unavailable with current settings: %s", c.When)
			}
		}

		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		script := c.Run + ` "$@"`
		shellArgs := append([]string{"-c", script, "sh"}, extraArgs...)

		// Signals received by tplater itself (Ctrl+C, etc.) are forwarded to the
		// executed command; see execx.Options.Signals and
		// execx.runWithSignalForwarding (it starts $SHELL in a separate process
		// group so the signal reaches the real program, not only the shell).
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
	*/
}

// availableNames returns sorted manifest command names for the "unknown
// command" error hint.
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
