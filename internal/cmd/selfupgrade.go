package cmd

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/selfupdate"
	"github.com/tplAIter/tplaiter/internal/state"
)

// runner — runner for self-update/suggest-check commands. A package variable
// (rather than execx.Exec{} directly in calls) lets unit tests replace it with
// [execx.RecordingRunner] without touching real git/go install.
var runner execx.Runner = execx.Exec{}

// detectInstallChannel wraps [selfupdate.DetectChannel] as a package variable
// so unit tests can provide a fixed channel. Real detection examines
// os.Executable()/BuildInfo of the current process; a `go test` binary matches
// none of the known paths and BuildInfo.Main.Version is usually "(devel),"
// so tests would always get [selfupdate.ChannelUnknown].
var detectInstallChannel = selfupdate.DetectChannel

// suggestCheckTimeout — upper bound for the `git ls-remote` network request in
// the background suggest check: update checks must not noticeably slow normal
// commands even when the repository is unavailable or slow.
const suggestCheckTimeout = 2 * time.Second

// suggestSkip — top-level commands for which the suggest check is meaningless:
// help/version and completion are already covered by firstRunSkip for the same
// reasons (see firstrun.go), plus self-upgrade (no point suggesting --upgrade
// during its own execution) and init-shell (an alias
// completion).
var suggestSkip = map[string]bool{
	"help":         true,
	"version":      true,
	"completion":   true,
	"init-shell":   true,
	"self-upgrade": true,
}

// suggestUpdatePreRun — part of the root command's PersistentPreRunE (see
// [rootPreRun] in root.go): an unobtrusive background check for a new version
// once every 24 hours. It never returns an error or interrupts the invoking
// command; [selfupdate.MaybeSuggest] owns all gates and error suppression,
// while this function only assembles arguments (home, network timeout, output).
func suggestUpdatePreRun(cmd *cobra.Command, _ []string) {
	if suggestSkip[topLevelCommand(cmd).Name()] {
		return
	}
	home, err := state.Home()
	if err != nil {
		return
	}

	parent := cmd.Context()
	if parent == nil {
		// cmd.Context() is nil only when PersistentPreRunE is called outside
		// cobra Execute()/ExecuteContext() (for example, directly from a unit test
		// on a synthetic *cobra.Command); in real execution cobra sets at least
		// context.Background() before the preRun chain.
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, suggestCheckTimeout)
	defer cancel()

	selfupdate.MaybeSuggest(ctx, runner, home, resolveVersion(), time.Now(), cmd.ErrOrStderr())
}

// newSelfUpgradeCmd creates `tplaiter self-upgrade` (the root
// `tplaiter --upgrade` alias; see root.go) for CLI self-updates.
func newSelfUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "self-upgrade",
		Short: "Обновить tplaiter до последней версии",
		Args:  cobra.NoArgs,
		RunE:  runSelfUpgrade,
	}
}

// runSelfUpgrade determines the installation channel, compares the current
// version with the latest tag in the canonical repository ([selfupdate.RepoURL]),
// and updates or prints instructions for channels that cannot be automated.
// A version-check failure (network unavailable, etc.) does not stop the command;
// the update is still attempted, just without a preliminary "vX.Y.Z is
// available" message.
func runSelfUpgrade(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	current := resolveVersion()

	if latest, err := selfupdate.LatestTag(ctx, runner, selfupdate.RepoURL()); err == nil && latest != "" {
		switch selfupdate.Compare(current, latest) {
		case selfupdate.CompareUpToDate:
			fmt.Fprintf(out, "уже установлена последняя версия (%s)\n", current)
			return nil
		case selfupdate.CompareAhead:
			fmt.Fprintf(out, "текущая версия (%s) новее последнего тега (%s) — обновление не требуется\n", current, latest)
			return nil
		case selfupdate.CompareOutdated:
			fmt.Fprintf(out, "доступна новая версия: %s -> %s\n", current, latest)
		case selfupdate.CompareUnknown:
			// current is not SemVer (usually a "dev" build): continue below;
			// comparison does not prevent attempting an update.
		}
	}

	return selfupdate.Upgrade(ctx, runner, detectInstallChannel(), mainModulePath(), out)
}

// mainModulePath returns the current process's Go module path
// (debug.BuildInfo.Main.Path), the argument for `go install <modulePath>@latest`
// in [selfupdate.Upgrade]. It returns an empty string when BuildInfo is
// unavailable (a non-module build, not expected in practice for go install).
func mainModulePath() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return info.Main.Path
}

// initShellGenerators maps supported init-shell names to cobra completion
// generators — `tplaiter init-shell <shell>` prints the same script as the
// built-in `tplaiter completion <shell>`.
var initShellGenerators = map[string]func(cmd *cobra.Command) error{
	"bash": func(cmd *cobra.Command) error { return cmd.Root().GenBashCompletionV2(cmd.OutOrStdout(), true) },
	"zsh":  func(cmd *cobra.Command) error { return cmd.Root().GenZshCompletion(cmd.OutOrStdout()) },
	"fish": func(cmd *cobra.Command) error { return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true) },
}

// newInitShellCmd creates `tplaiter init-shell [bash|zsh|fish]`, a thin alias
// over cobra's built-in `completion` with a short hint about where to put the
// output for permanent loading.
func newInitShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init-shell [bash|zsh|fish]",
		Short: "Скрипт автодополнения shell (алиас `tplaiter completion <shell>`)",
		Long: "init-shell печатает скрипт автодополнения tplaiter для указанной оболочки — " +
			"то же самое, что встроенная `tplaiter completion <shell>`.\n\n" +
			"Разовая загрузка в текущей сессии:\n  source <(tplaiter init-shell bash)\n\n" +
			"Постоянная загрузка — допишите вызов выше в ~/.bashrc / ~/.zshrc, либо для fish " +
			"сохраните вывод в ~/.config/fish/completions/tplaiter.fish.",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return initShellGenerators[args[0]](cmd)
		},
	}
}
