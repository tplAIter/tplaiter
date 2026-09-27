package selfupdate

import (
	"context"
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Upgrade выполняет самообновление tplater согласно каналу установки channel
//:
//   - [ChannelGoInstall]: `go install <modulePath>@latest`, стримя вывод в out;
//   - [ChannelBrew]: печатает подсказку `brew upgrade tplater` (brew сам
//     управляет своими пакетами — вызывать его от имени tplater не входит в
//     MVP, см.  "дополнительно, не MVP");
//   - иначе (канал не распознан): печатает обе инструкции как fallback,
//     чтобы пользователь выбрал подходящую вручную.
//
// modulePath — путь Go-модуля для go install (обычно
// debug.BuildInfo.Main.Path текущего процесса, см. internal/cmd/version.go).
// Пустой modulePath при [ChannelGoInstall] — ошибка: без пути модуля
// `go install ...@latest` невозможно сформировать.
func Upgrade(ctx context.Context, runner execx.Runner, channel Channel, modulePath string, out io.Writer) error {
	switch channel {
	case ChannelGoInstall:
		return upgradeGoInstall(ctx, runner, modulePath, out)
	case ChannelBrew:
		fmt.Fprintln(out, "Канал установки — Homebrew. Выполните обновление командой:")
		printBrewInstruction(out)
		return nil
	default:
		fmt.Fprintln(out, "Канал установки tplater не распознан — обновите вручную одним из способов:")
		printGoInstallInstruction(out, modulePath)
		printBrewInstruction(out)
		return nil
	}
}

func upgradeGoInstall(ctx context.Context, runner execx.Runner, modulePath string, out io.Writer) error {
	if modulePath == "" {
		return fmt.Errorf("selfupdate: upgrade: канал %s, но путь Go-модуля не определён (пустой debug.BuildInfo.Main.Path)", ChannelGoInstall)
	}

	target := modulePath + "@latest"
	fmt.Fprintf(out, "go install %s\n", target)

	if _, err := runner.Run(ctx, "go", []string{"install", target}, execx.Options{Stdout: out, Stderr: out}); err != nil {
		return fmt.Errorf("selfupdate: go install %s: %w", target, err)
	}

	fmt.Fprintln(out, "Готово — изменения вступят в силу при следующем запуске tplater.")
	return nil
}

func printGoInstallInstruction(out io.Writer, modulePath string) {
	if modulePath == "" {
		modulePath = "<module>"
	}
	fmt.Fprintf(out, "  go install %s@latest\n", modulePath)
}

func printBrewInstruction(out io.Writer) {
	fmt.Fprintln(out, "  brew upgrade tplater")
}
