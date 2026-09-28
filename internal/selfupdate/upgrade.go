package selfupdate

import (
	"context"
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Upgrade performs a tplater self-update according to installation channel
// :
//   - [ChannelGoInstall]: `go install <modulePath>@latest`, streaming output to out;
//   - [ChannelBrew]: prints `brew upgrade tplater` (brew manages its own
//     packages, so invoking it from tplater is outside the MVP);
//   - otherwise (unknown channel): prints both instructions as a fallback for
//     the user to choose manually.
//
// modulePath is the Go module path for go install (usually
// debug.BuildInfo.Main.Path of the current process, see internal/cmd/version.go).
// An empty modulePath with [ChannelGoInstall] is an error: without a module path
// `go install ...@latest` cannot be formed.
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
