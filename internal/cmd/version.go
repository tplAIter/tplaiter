package cmd

import (
	"fmt"
	"path/filepath"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/selfupdate"
	"github.com/tplAIter/tplaiter/internal/state"
)

// version — версия CLI. Подставляется линкером при релизной сборке
// (-ldflags "-X .../internal/cmd.version=vX.Y.Z", см. Makefile). Если пуста
// (локальная сборка `go build .` / `go run .`), версия определяется через
// runtime/debug.BuildInfo — при `go install module@vX.Y.Z` Go сам проставляет
// info.Main.Version. Если и это недоступно — печатаем "dev".
var version = ""

// resolveVersion возвращает версию CLI в порядке приоритета:
// ldflags-переменная -> runtime/debug.BuildInfo -> "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if v := buildInfoVersion(debug.ReadBuildInfo); v != "" {
		return v
	}
	return "dev"
}

// buildInfoVersion извлекает версию модуля из BuildInfo. Параметризовано
// функцией чтения для тестируемости (без реальной сборки через go install).
func buildInfoVersion(read func() (*debug.BuildInfo, bool)) string {
	info, ok := read()
	if !ok {
		return ""
	}
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}

// unknownRevision — заполнитель, когда commit-хэш недоступен (например,
// локальная сборка без VCS-метаданных, см. [buildRevision]).
const unknownRevision = "неизвестен"

// buildRevision извлекает vcs.revision (короткий commit-хэш) из
// BuildInfo.Settings — Go проставляет его автоматически при сборке из VCS
// (go install/go build внутри git-репозитория). Параметризовано функцией
// чтения, как [buildInfoVersion] — для тестируемости без реальной сборки.
func buildRevision(read func() (*debug.BuildInfo, bool)) string {
	info, ok := read()
	if !ok {
		return unknownRevision
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	return unknownRevision
}

// newVersionCmd создаёт команду `tplaiter version`: версия, commit, канал
// установки ( см. internal/selfupdate.DetectChannel) и путь
// конфига (~/.tplaiter/config.yaml либо TPLAITER_HOME).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию tplaiter",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, resolveVersion())
			fmt.Fprintln(out, "commit:", buildRevision(debug.ReadBuildInfo))
			fmt.Fprintln(out, "канал установки:", selfupdate.DetectChannel().Label())
			if home, err := state.Home(); err == nil {
				fmt.Fprintln(out, "конфиг:", filepath.Join(home, "config.yaml"))
			}
			return nil
		},
	}
}
