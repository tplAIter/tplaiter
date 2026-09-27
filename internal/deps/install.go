package deps

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// ActionKind — вид действия, которое [InstallPlan] предлагает для установки
// инструмента на данной платформе.
type ActionKind string

// Виды действий установки.
const (
	// ActionBrew — установка одной командой `brew install <formula>`
	// (доступна на darwin и linux, если в PATH есть brew).
	ActionBrew ActionKind = "brew"
	// ActionAptPrint — apt-рецепт только печатается (sudo не вызываем сами).
	ActionAptPrint ActionKind = "apt-print"
	// ActionURL — нет автоматического рецепта, печатаем ссылку на ручную
	// установку.
	ActionURL ActionKind = "url"
	// ActionNone — для платформы/инструмента вовсе нет рецепта установки.
	ActionNone ActionKind = "none"
)

// Action — план установки инструмента, вычисленный [InstallPlan]. Command —
// готовая к печати/исполнению команда (для ActionBrew — то, что реально
// исполняется; для ActionAptPrint/ActionURL — то, что только печатается).
type Action struct {
	Kind    ActionKind
	Command string
}

// Platform — платформенный контекст, влияющий на выбор рецепта установки.
type Platform struct {
	// GOOS — целевая ОС (обычно runtime.GOOS, параметризовано для тестов).
	GOOS string
	// HasBrew сообщает, найден ли brew в PATH текущего окружения.
	HasBrew bool
}

// InstallPlan выбирает рецепт установки tool для platform:
//  1. brew, если он есть в PATH (darwin или linux) и манифест даёт формулу;
//  2. apt — только когда brew недоступен на linux (иначе brew в приоритете);
//  3. url — если задана ссылка на ручную установку;
//  4. none — для этой платформы у инструмента вовсе нет рецепта.
func InstallPlan(tool manifest.Tool, platform Platform) Action {
	switch {
	case platform.HasBrew && (platform.GOOS == "darwin" || platform.GOOS == "linux") && tool.Install.Brew != "":
		return Action{Kind: ActionBrew, Command: "brew install " + tool.Install.Brew}
	case platform.GOOS == "linux" && !platform.HasBrew && tool.Install.Apt != "":
		return Action{Kind: ActionAptPrint, Command: "sudo apt install " + tool.Install.Apt}
	case tool.Install.URL != "":
		return Action{Kind: ActionURL, Command: tool.Install.URL}
	default:
		return Action{Kind: ActionNone}
	}
}

// UI — минимальный вывод, нужный установке инструментов: сообщения со
// смысловой раскраской и писатель для стриминга вывода дочерних процессов
// (например, `brew install`) по мере его появления.
type UI struct {
	Out     io.Writer
	Palette ui.Palette
}

// NewUI создаёт UI поверх writer out с палитрой pal.
func NewUI(out io.Writer, pal ui.Palette) UI {
	return UI{Out: out, Palette: pal}
}

// Info печатает нейтральное сообщение.
func (u UI) Info(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Muted(msg))
}

// Warn печатает предупреждение.
func (u UI) Warn(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Warn(msg))
}

// Success печатает сообщение об успехе.
func (u UI) Success(msg string) {
	fmt.Fprintln(u.Out, u.Palette.Success(msg))
}

// DetectPlatform определяет [Platform] текущего процесса: GOOS runtime и
// наличие brew в PATH через runner.LookPath — благодаря этому unit-тесты
// управляют HasBrew через [execx.RecordingRunner.SetLookPath] без обращения
// к реальной машине.
func DetectPlatform(runner execx.Runner) Platform {
	_, err := runner.LookPath("brew")
	return Platform{GOOS: runtime.GOOS, HasBrew: err == nil}
}

// Install выполняет план установки tool, вычисленный по текущей платформе
// (см. [DetectPlatform], [InstallPlan]):
//   - ActionBrew — печатает предложение, спрашивает confirm() и, если true,
//     исполняет `brew install <formula>`, стримя вывод в out.Out;
//   - ActionAptPrint/ActionURL — только печатает рецепт, ничего не исполняет
//     (sudo руками пользователя);
//   - ActionNone — предупреждает об отсутствии рецепта.
//
// confirm может быть nil — эквивалентно функции, всегда возвращающей false
// (установка не подтверждена, план всё равно возвращается вызывающему).
func Install(ctx context.Context, runner execx.Runner, out UI, tool manifest.Tool, confirm func() bool) (Action, error) {
	return installFor(ctx, runner, out, tool, DetectPlatform(runner), confirm)
}

// installFor — реализация [Install], параметризованная по platform, чтобы
// юниты могли фиксировать GOOS/HasBrew независимо от машины, на которой
// выполняются тесты (см. check_test.go/install_test.go: реальный
// runtime.GOOS хоста CI не должен решать, какая ветка InstallPlan
// проверяется).
func installFor(ctx context.Context, runner execx.Runner, out UI, tool manifest.Tool, platform Platform, confirm func() bool) (Action, error) {
	action := InstallPlan(tool, platform)

	switch action.Kind {
	case ActionBrew:
		out.Info(tool.Name + ": установка доступна через brew — " + action.Command)
		if confirm == nil || !confirm() {
			out.Info(tool.Name + ": установка отменена")
			return action, nil
		}
		_, err := runner.Run(ctx, "brew", []string{"install", tool.Install.Brew}, execx.Options{
			Stdout: out.Out,
			Stderr: out.Out,
		})
		if err != nil {
			return action, fmt.Errorf("deps: brew install %s: %w", tool.Install.Brew, err)
		}
		out.Success(tool.Name + ": установлен через brew")
		return action, nil
	case ActionAptPrint:
		out.Warn(tool.Name + ": автоматическая установка недоступна, выполните вручную:")
		out.Info("  " + action.Command)
		return action, nil
	case ActionURL:
		out.Warn(tool.Name + ": нет пакетного рецепта для этой платформы, установите вручную:")
		out.Info("  " + action.Command)
		return action, nil
	default:
		out.Warn(tool.Name + ": нет рецепта установки для этой платформы")
		return action, nil
	}
}
