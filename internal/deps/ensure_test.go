package deps

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func TestEnsureTools_AllSatisfiedNoInstallAttempted(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("go", "/usr/local/bin/go")
	runner.OnCommand("go", execx.Response{Result: execx.Result{Stdout: "go version go1.26.4 darwin/arm64\n"}})

	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tools := []manifest.Tool{{Name: "go", Version: ">=1.26.0", Required: true}}

	if err := EnsureTools(context.Background(), runner, out, tools, EnsureOptions{}); err != nil {
		t.Fatalf("EnsureTools() error = %v", err)
	}
	if containsCallByName(runner.Calls, "brew") {
		t.Error("не должно быть попытки установки, когда инструмент уже удовлетворяет требованиям")
	}
}

func TestEnsureTools_RequiredMissingFailsWithoutInstall(t *testing.T) {
	runner := execx.NewRecordingRunner()
	// git не найден и SkipInstall выставлен — установка не предлагается.

	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tools := []manifest.Tool{{Name: "git", Required: true}}

	err := EnsureTools(context.Background(), runner, out, tools, EnsureOptions{SkipInstall: true})
	if err == nil {
		t.Fatal("EnsureTools() error = nil, want error (required-инструмент отсутствует)")
	}
	if !errors.Is(err, ErrMissingRequiredTools) {
		t.Errorf("errors.Is(err, ErrMissingRequiredTools) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "git") {
		t.Errorf("err = %v, want mention of git", err)
	}
}

func TestEnsureTools_RequiredFalseMissingIsOnlyWarning(t *testing.T) {
	runner := execx.NewRecordingRunner()
	// docker не найден, но Required=false.

	var buf bytes.Buffer
	out := NewUI(&buf, ui.NewPalette(false))
	tools := []manifest.Tool{{Name: "docker", Required: false}}

	err := EnsureTools(context.Background(), runner, out, tools, EnsureOptions{SkipInstall: true})
	if err != nil {
		t.Fatalf("EnsureTools() error = %v, want nil (required=false -> warning, не провал)", err)
	}
	if !strings.Contains(buf.String(), "docker") {
		t.Errorf("output = %q, want warning mentioning docker", buf.String())
	}
}

func TestEnsureTools_AutoYesInstallsMissingRequiredViaBrew(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")
	// go не найден до установки: первый LookPath("go") -> ошибка. После
	// brew install скрипт для повторной проверки должен вернуть успех —
	// RecordingRunner.SetLookPath перезатирает предыдущий скрипт.
	runner.On("brew", []string{"install", "golang"}, execx.Response{
		Result: execx.Result{Stdout: "==> Installing golang\n"},
	})

	// LookPath("go") без скрипта -> ошибка "не найден". Чтобы имитировать
	// «появление после установки», перед EnsureTools нельзя просто
	// подставить путь — тест проверяет, что brew install действительно
	// вызывается с --yes без интерактива, а не последующее появление в PATH
	// (это оркестрируется реальной ОС, а не этим пакетом).
	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tools := []manifest.Tool{{Name: "go", Required: true, Install: manifest.ToolInstall{Brew: "golang"}}}

	err := EnsureTools(context.Background(), runner, out, tools, EnsureOptions{AutoYes: true})

	if !containsBrewInstallGolang(runner.Calls) {
		t.Errorf("Calls = %+v, want brew install golang вызванным без интерактивного подтверждения (AutoYes)", runner.Calls)
	}
	// go всё ещё не найден повторной проверкой (мы не подкладывали
	// LookPath после install) -> required-инструмент так и не в порядке.
	if err == nil {
		t.Fatal("EnsureTools() error = nil, want error (go всё ещё не в PATH после install в этом сценарии)")
	}
	if !errors.Is(err, ErrMissingRequiredTools) {
		t.Errorf("errors.Is(err, ErrMissingRequiredTools) = false, err = %v", err)
	}
}

func TestEnsureTools_SkipInstallNeverCallsInstall(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")

	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tools := []manifest.Tool{{Name: "go", Required: false, Install: manifest.ToolInstall{Brew: "golang"}}}

	if err := EnsureTools(context.Background(), runner, out, tools, EnsureOptions{SkipInstall: true, AutoYes: true}); err != nil {
		t.Fatalf("EnsureTools() error = %v", err)
	}
	if containsBrewInstallGolang(runner.Calls) {
		t.Error("SkipInstall должен подавлять любые попытки установки")
	}
}

func containsCallByName(calls []execx.Call, name string) bool {
	for _, c := range calls {
		if c.Name == name {
			return true
		}
	}
	return false
}
