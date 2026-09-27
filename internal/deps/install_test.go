package deps

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func TestInstallPlan(t *testing.T) {
	cases := []struct {
		name     string
		tool     manifest.Tool
		platform Platform
		want     ActionKind
	}{
		{
			name:     "darwin+brew formula",
			tool:     manifest.Tool{Install: manifest.ToolInstall{Brew: "go"}},
			platform: Platform{GOOS: "darwin", HasBrew: true},
			want:     ActionBrew,
		},
		{
			name:     "linux+brew formula",
			tool:     manifest.Tool{Install: manifest.ToolInstall{Brew: "go"}},
			platform: Platform{GOOS: "linux", HasBrew: true},
			want:     ActionBrew,
		},
		{
			name:     "linux без brew с apt-рецептом",
			tool:     manifest.Tool{Install: manifest.ToolInstall{Apt: "golang-go"}},
			platform: Platform{GOOS: "linux", HasBrew: false},
			want:     ActionAptPrint,
		},
		{
			name:     "linux без brew, только url",
			tool:     manifest.Tool{Install: manifest.ToolInstall{URL: "https://go.dev/dl/"}},
			platform: Platform{GOOS: "linux", HasBrew: false},
			want:     ActionURL,
		},
		{
			name:     "нет ни одного рецепта",
			tool:     manifest.Tool{},
			platform: Platform{GOOS: "linux", HasBrew: false},
			want:     ActionNone,
		},
		{
			name:     "brew есть, но у инструмента только apt-рецепт",
			tool:     manifest.Tool{Install: manifest.ToolInstall{Apt: "golang-go"}},
			platform: Platform{GOOS: "linux", HasBrew: true},
			want:     ActionNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InstallPlan(tc.tool, tc.platform)
			if got.Kind != tc.want {
				t.Errorf("InstallPlan() = %+v, want Kind %v", got, tc.want)
			}
		})
	}
}

func TestInstall_BrewConfirmYesRunsInstall(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")
	runner.On("brew", []string{"install", "golang"}, execx.Response{
		Result: execx.Result{Stdout: "==> Installing golang\n==> Summary\n"},
	})

	var buf bytes.Buffer
	out := NewUI(&buf, ui.NewPalette(false))
	tool := manifest.Tool{Name: "go", Install: manifest.ToolInstall{Brew: "golang"}}

	action, err := Install(context.Background(), runner, out, tool, func() bool { return true })
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if action.Kind != ActionBrew {
		t.Errorf("action.Kind = %v, want ActionBrew", action.Kind)
	}
	if !containsBrewInstallGolang(runner.Calls) {
		t.Errorf("Calls = %+v, want a call to brew install golang", runner.Calls)
	}
	if !strings.Contains(buf.String(), "Installing golang") {
		t.Errorf("output = %q, want streamed brew output", buf.String())
	}
}

func TestInstall_BrewConfirmNoDoesNotInstall(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")

	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tool := manifest.Tool{Name: "go", Install: manifest.ToolInstall{Brew: "golang"}}

	action, err := Install(context.Background(), runner, out, tool, func() bool { return false })
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if action.Kind != ActionBrew {
		t.Errorf("action.Kind = %v, want ActionBrew (план всё равно вычислен)", action.Kind)
	}
	if containsBrewInstallGolang(runner.Calls) {
		t.Errorf("Calls = %+v, install не должен был выполняться при confirm()=false", runner.Calls)
	}
}

func TestInstall_NilConfirmDoesNotInstall(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")

	out := NewUI(&bytes.Buffer{}, ui.NewPalette(false))
	tool := manifest.Tool{Name: "go", Install: manifest.ToolInstall{Brew: "golang"}}

	if _, err := Install(context.Background(), runner, out, tool, nil); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if containsBrewInstallGolang(runner.Calls) {
		t.Error("nil confirm должен трактоваться как отказ от установки")
	}
}

func TestInstallFor_AptOnlyPrintsAndDoesNotExecute(t *testing.T) {
	runner := execx.NewRecordingRunner()
	var buf bytes.Buffer
	out := NewUI(&buf, ui.NewPalette(false))
	tool := manifest.Tool{Name: "ansible", Install: manifest.ToolInstall{Apt: "ansible"}}
	platform := Platform{GOOS: "linux", HasBrew: false}

	action, err := installFor(context.Background(), runner, out, tool, platform, func() bool { return true })
	if err != nil {
		t.Fatalf("installFor() error = %v", err)
	}
	if action.Kind != ActionAptPrint {
		t.Fatalf("action.Kind = %v, want ActionAptPrint", action.Kind)
	}
	if len(runner.Calls) != 0 {
		t.Errorf("Calls = %+v, apt-рецепт не должен исполняться, только печататься", runner.Calls)
	}
	if !strings.Contains(buf.String(), "sudo apt install ansible") {
		t.Errorf("output = %q, want printed apt command", buf.String())
	}
}

func TestInstallFor_URLOnlyPrints(t *testing.T) {
	runner := execx.NewRecordingRunner()
	var buf bytes.Buffer
	out := NewUI(&buf, ui.NewPalette(false))
	tool := manifest.Tool{Name: "docker", Install: manifest.ToolInstall{URL: "https://docs.docker.com/get-docker/"}}
	platform := Platform{GOOS: "linux", HasBrew: false}

	action, err := installFor(context.Background(), runner, out, tool, platform, nil)
	if err != nil {
		t.Fatalf("installFor() error = %v", err)
	}
	if action.Kind != ActionURL {
		t.Fatalf("action.Kind = %v, want ActionURL", action.Kind)
	}
	if len(runner.Calls) != 0 {
		t.Errorf("Calls = %+v, url-рецепт ничего не исполняет", runner.Calls)
	}
	if !strings.Contains(buf.String(), "https://docs.docker.com/get-docker/") {
		t.Errorf("output = %q, want printed URL", buf.String())
	}
}

func TestInstallFor_NoneWarns(t *testing.T) {
	runner := execx.NewRecordingRunner()
	var buf bytes.Buffer
	out := NewUI(&buf, ui.NewPalette(false))
	tool := manifest.Tool{Name: "mystery"}
	platform := Platform{GOOS: "linux", HasBrew: false}

	action, err := installFor(context.Background(), runner, out, tool, platform, nil)
	if err != nil {
		t.Fatalf("installFor() error = %v", err)
	}
	if action.Kind != ActionNone {
		t.Fatalf("action.Kind = %v, want ActionNone", action.Kind)
	}
	if buf.Len() == 0 {
		t.Error("output пуст, want предупреждение об отсутствии рецепта")
	}
}

func TestDetectPlatform(t *testing.T) {
	withBrew := execx.NewRecordingRunner()
	withBrew.SetLookPath("brew", "/opt/homebrew/bin/brew")
	if p := DetectPlatform(withBrew); !p.HasBrew {
		t.Error("HasBrew = false, want true when brew is in PATH")
	}

	withoutBrew := execx.NewRecordingRunner()
	if p := DetectPlatform(withoutBrew); p.HasBrew {
		t.Error("HasBrew = true, want false when brew is not in PATH")
	}
}

// containsBrewInstallGolang сообщает, есть ли среди calls вызов `brew
// install golang` — единственная формула, которую скриптуют тесты этого
// пакета (без параметра — иначе unparam справедливо ругается на
// неиспользуемую гибкость).
func containsBrewInstallGolang(calls []execx.Call) bool {
	args := []string{"install", "golang"}
	for _, c := range calls {
		if c.Name != "brew" || len(c.Args) != len(args) {
			continue
		}
		match := true
		for i := range args {
			if c.Args[i] != args[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
