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

// runner — Runner для команд самообновления/suggest-проверки. Переменная
// пакета (а не execx.Exec{} напрямую в вызовах) — юниты подменяют её
// [execx.RecordingRunner], не трогая реальные git/go install.
var runner execx.Runner = execx.Exec{}

// detectInstallChannel — обёртка над [selfupdate.DetectChannel] как
// переменная пакета: юниты подставляют фиксированный канал. Нужна, потому
// что реальная детекция смотрит на os.Executable()/BuildInfo текущего
// процесса — у тестового бинарника (`go test`) это ни один из известных
// путей и BuildInfo.Main.Version почти всегда "(devel)", так что
// [selfupdate.DetectChannel] в тестах стабильно вернул бы [selfupdate.ChannelUnknown]
// независимо от того, что тест хочет проверить.
var detectInstallChannel = selfupdate.DetectChannel

// suggestCheckTimeout — верхняя граница на сетевой поход `git ls-remote` в
// фоновой suggest-проверке: проверка обновлений не должна
// заметно замедлять обычные команды даже при недоступном/медленном
// репозитории.
const suggestCheckTimeout = 2 * time.Second

// suggestSkip — top-level команды, для которых suggest-проверка не имеет
// смысла: справка/версия и completion уже покрыты firstRunSkip по тем же
// причинам (см. firstrun.go), плюс сама self-upgrade (нет смысла
// подсказывать --upgrade прямо во время его выполнения) и init-shell (алиас
// completion).
var suggestSkip = map[string]bool{
	"help":         true,
	"version":      true,
	"completion":   true,
	"init-shell":   true,
	"self-upgrade": true,
}

// suggestUpdatePreRun — часть PersistentPreRunE корневой команды (см.
// [rootPreRun] в root.go): ненавязчивая фоновая проверка новой версии раз в
// 24ч. Никогда не возвращает ошибку и не прерывает выполнение вызывающей
// команды — вся логика гейтов/поглощения ошибок в
// [selfupdate.MaybeSuggest], здесь только сборка аргументов (home, таймаут
// на сеть, поток вывода).
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
		// cmd.Context() — nil, только если PersistentPreRunE вызван мимо
		// cobra Execute()/ExecuteContext() (например, напрямую из юнит-теста
		// на синтетическом *cobra.Command); в реальном запуске cobra всегда
		// проставляет как минимум context.Background() перед preRun-цепочкой.
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, suggestCheckTimeout)
	defer cancel()

	selfupdate.MaybeSuggest(ctx, runner, home, resolveVersion(), time.Now(), cmd.ErrOrStderr())
}

// newSelfUpgradeCmd создаёт команду `tplaiter self-upgrade` (алиас для флага
// `tplaiter --upgrade` на root, см. root.go) — самообновление CLI.
func newSelfUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "self-upgrade",
		Short: "Обновить tplaiter до последней версии",
		Args:  cobra.NoArgs,
		RunE:  runSelfUpgrade,
	}
}

// runSelfUpgrade определяет канал установки, сверяет текущую версию со
// старшим тегом канонического репозитория ([selfupdate.RepoURL]) и запускает
// обновление либо печатает инструкцию для неавтоматизируемых каналов
//. Сбой сверки версий (сеть недоступна и т.п.) не прерывает
// команду — обновление всё равно пробуется, просто без предварительного
// «доступна vX.Y.Z» сообщения.
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
			// current — не SemVer (обычно "dev"-сборка): продолжаем ниже,
			// сравнение не запрещает попытку обновиться.
		}
	}

	return selfupdate.Upgrade(ctx, runner, detectInstallChannel(), mainModulePath(), out)
}

// mainModulePath возвращает путь Go-модуля текущего процесса
// (debug.BuildInfo.Main.Path) — аргумент для `go install <modulePath>@latest`
// в [selfupdate.Upgrade]. Пустая строка, если BuildInfo недоступен (сборка
// без модульного режима — на практике не встречается для `go install`).
func mainModulePath() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return info.Main.Path
}

// initShellGenerators сопоставляет допустимые оболочки init-shell генератору
// автодополнения cobra — `tplaiter init-shell <shell>` печатает тот же скрипт,
// что встроенная `tplaiter completion <shell>`.
var initShellGenerators = map[string]func(cmd *cobra.Command) error{
	"bash": func(cmd *cobra.Command) error { return cmd.Root().GenBashCompletionV2(cmd.OutOrStdout(), true) },
	"zsh":  func(cmd *cobra.Command) error { return cmd.Root().GenZshCompletion(cmd.OutOrStdout()) },
	"fish": func(cmd *cobra.Command) error { return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true) },
}

// newInitShellCmd создаёт команду `tplaiter init-shell [bash|zsh|fish]` —
// тонкий алиас над встроенной cobra `completion` с короткой
// подсказкой, куда прописать вывод для постоянной загрузки.
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
