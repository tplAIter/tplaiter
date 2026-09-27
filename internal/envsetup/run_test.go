package envsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// ---- ListPlaybooks ----------------------------------------------------

func TestListPlaybooks_WhenFiltering(t *testing.T) {
	tpl := &manifest.Template{
		Environment: manifest.Environment{
			Playbooks: []manifest.Playbook{
				{Name: "setup", File: "environment/setup.yml", Description: "зависимости"},
				{Name: "infra", File: "environment/infra.yml", Description: "инфра", When: "database=postgres"},
				{Name: "unreachable", File: "environment/x.yml", When: "database=mysql"},
				{Name: "broken", File: "environment/y.yml", When: "unknown_group=x"},
			},
		},
	}
	values := settings.Values{"database": "postgres"}

	got := ListPlaybooks(tpl, values)
	if len(got) != 4 {
		t.Fatalf("ListPlaybooks() returned %d entries, want 4", len(got))
	}

	want := map[string]bool{
		"setup":       true,
		"infra":       true,
		"unreachable": false,
		"broken":      false,
	}
	for _, info := range got {
		if info.Available != want[info.Name] {
			t.Errorf("%s: Available = %v, want %v", info.Name, info.Available, want[info.Name])
		}
	}

	if got[1].WhenStr != "database=postgres" {
		t.Errorf("infra.WhenStr = %q, want %q", got[1].WhenStr, "database=postgres")
	}
	if got[0].WhenStr != "" {
		t.Errorf("setup.WhenStr = %q, want empty (нет when)", got[0].WhenStr)
	}
}

func TestListPlaybooks_Empty(t *testing.T) {
	tpl := &manifest.Template{}
	if got := ListPlaybooks(tpl, settings.Values{}); len(got) != 0 {
		t.Errorf("ListPlaybooks() = %+v, want empty slice", got)
	}
}

// ---- buildExtraVars -----------------------------------------------------

func TestBuildExtraVars_JSONShape(t *testing.T) {
	values := settings.Values{
		"database": "postgres",
		"brokers":  []string{"kafka", "rabbitmq"},
		"cache":    true,
	}
	proj := manifest.ProjectInfo{
		Name:   "My Service",
		Slug:   "my-service",
		Module: "example.com/my-service",
		System: "billing",
		Domain: "payments",
	}

	raw, err := buildExtraVars(values, proj)
	if err != nil {
		t.Fatalf("buildExtraVars() error = %v", err)
	}

	var decoded struct {
		Tplater struct {
			Project struct {
				Name   string `json:"name"`
				Slug   string `json:"slug"`
				Module string `json:"module"`
				System string `json:"system"`
				Domain string `json:"domain"`
			} `json:"project"`
			Settings map[string]any `json:"settings"`
		} `json:"tplaiter"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", raw, err)
	}

	p := decoded.Tplater.Project
	if p.Name != proj.Name || p.Slug != proj.Slug || p.Module != proj.Module || p.System != proj.System || p.Domain != proj.Domain {
		t.Errorf("decoded project = %+v, want %+v", p, proj)
	}

	if decoded.Tplater.Settings["database"] != "postgres" {
		t.Errorf("settings.database = %v, want postgres", decoded.Tplater.Settings["database"])
	}
	brokers, ok := decoded.Tplater.Settings["brokers"].([]any)
	if !ok || len(brokers) != 2 || brokers[0] != "kafka" || brokers[1] != "rabbitmq" {
		t.Errorf("settings.brokers = %v, want [kafka rabbitmq]", decoded.Tplater.Settings["brokers"])
	}
	if decoded.Tplater.Settings["cache"] != true {
		t.Errorf("settings.cache = %v, want true", decoded.Tplater.Settings["cache"])
	}
}

func TestBuildExtraVars_NilValues(t *testing.T) {
	raw, err := buildExtraVars(nil, manifest.ProjectInfo{Name: "x"})
	if err != nil {
		t.Fatalf("buildExtraVars() error = %v", err)
	}
	if !strings.Contains(raw, `"settings": {}`) {
		t.Errorf("raw = %s, want settings serialized as empty object, not null", raw)
	}
}

// ---- RunPlaybook: extra-vars file / args ---------------------------------

func TestRunPlaybook_PassesExtraVarsFileAndProjectRoot(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible-playbook", "/usr/local/bin/ansible-playbook")
	runner.OnCommand("ansible-playbook", execx.Response{Result: execx.Result{Stdout: "PLAY [setup]\n"}})

	var out bytes.Buffer
	r := &Runner{
		Exec:   runner,
		UI:     deps.NewUI(&out, ui.NewPalette(false)),
		DepsUI: deps.NewUI(&out, ui.NewPalette(false)),
	}

	proj := manifest.ProjectInfo{Name: "svc", Slug: "svc"}
	values := settings.Values{"database": "postgres"}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/project/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
		Values:      values,
		Project:     proj,
	})
	assertAnsibleDenied(t, err, runner.Calls)
	if len(runner.Calls) > 0 {

		if len(runner.Calls) != 1 {
			t.Fatalf("Calls = %+v, want exactly 1 call to ansible-playbook", runner.Calls)
		}
		call := runner.Calls[0]
		if call.Name != "ansible-playbook" {
			t.Fatalf("call.Name = %q, want ansible-playbook", call.Name)
		}
		if len(call.Args) != 5 {
			t.Fatalf("call.Args = %+v, want 5 elements", call.Args)
		}
		if call.Args[0] != filepath.Join(dir, "setup.yml") {
			t.Errorf("call.Args[0] = %q, want playbook path", call.Args[0])
		}
		if call.Args[1] != "--extra-vars" {
			t.Errorf("call.Args[1] = %q, want --extra-vars", call.Args[1])
		}
		if !strings.HasPrefix(call.Args[2], "@") {
			t.Fatalf("call.Args[2] = %q, want @<path>", call.Args[2])
		}
		extraVarsPath := strings.TrimPrefix(call.Args[2], "@")
		if call.Args[3] != "-e" {
			t.Errorf("call.Args[3] = %q, want -e", call.Args[3])
		}
		if call.Args[4] != "tplater_project_root=/project/root" {
			t.Errorf("call.Args[4] = %q, want tplater_project_root=/project/root", call.Args[4])
		}
		if call.Opts.Dir != "/project/root" {
			t.Errorf("call.Opts.Dir = %q, want /project/root", call.Opts.Dir)
		}

		// Файл должен существовать МОМЕНТ вызова (проверяем это отдельно через
		// buildExtraVars — здесь важно, что путь был передан корректно и что файл
		// удалён ПОСЛЕ завершения RunPlaybook).
		if _, err := os.Stat(extraVarsPath); !os.IsNotExist(err) {
			t.Errorf("extra-vars файл %s не удалён после RunPlaybook (err=%v)", extraVarsPath, err)
		}

		if !strings.Contains(out.String(), "PLAY [setup]") {
			t.Errorf("output = %q, want streamed ansible-playbook stdout", out.String())
		}
	}
}

func TestRunPlaybook_ExtraVarsFileContentMatchesBuildExtraVars(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	proj := manifest.ProjectInfo{Name: "svc", Slug: "svc", Module: "example.com/svc"}
	values := settings.Values{"database": "postgres"}

	// RunPlaybook удаляет временный файл extra-vars сразу после возврата из
	// Run (defer) — единственный момент, когда файл гарантированно ещё
	// существует, это ВНУТРИ самого вызова Run. capturingRunner читает его
	// оттуда, пока RecordingRunner формирует ответ.
	var fileContent string
	runner := &capturingRunner{
		RecordingRunner: execx.NewRecordingRunner(),
		onRunSync: func(args []string) {
			for i, a := range args {
				if a == "--extra-vars" && i+1 < len(args) {
					path := strings.TrimPrefix(args[i+1], "@")
					data, readErr := os.ReadFile(path)
					if readErr != nil {
						t.Fatalf("чтение extra-vars файла %s: %v", path, readErr)
					}
					fileContent = string(data)
				}
			}
		},
	}
	runner.SetLookPath("ansible-playbook", "/usr/local/bin/ansible-playbook")
	runner.OnCommand("ansible-playbook", execx.Response{Result: execx.Result{}})

	var out bytes.Buffer
	r := &Runner{Exec: runner, UI: deps.NewUI(&out, ui.NewPalette(false)), DepsUI: deps.NewUI(&out, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
		Values:      values,
		Project:     proj,
	})
	assertAnsibleDenied(t, err, runner.Calls)
	if len(runner.Calls) > 0 {

		want, err := buildExtraVars(values, proj)
		if err != nil {
			t.Fatalf("buildExtraVars() error = %v", err)
		}
		if fileContent != want {
			t.Errorf("файл extra-vars = %s, want %s", fileContent, want)
		}
	}
}

// capturingRunner — тестовый Runner, вызывающий onRunSync с аргументами Run
// ДО делегирования RecordingRunner (файл extra-vars ещё существует к этому
// моменту — RunPlaybook удаляет его только после возврата из Run).
type capturingRunner struct {
	*execx.RecordingRunner
	onRunSync func(args []string)
}

func (r *capturingRunner) Run(ctx context.Context, name string, args []string, opts execx.Options) (execx.Result, error) {
	if r.onRunSync != nil {
		r.onRunSync(args)
	}
	return r.RecordingRunner.Run(ctx, name, args, opts)
}

// ---- RunPlaybook: несуществующий playbook-файл ---------------------------

func TestRunPlaybook_MissingPlaybookFile(t *testing.T) {
	dir := t.TempDir()

	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible-playbook", "/usr/local/bin/ansible-playbook")

	r := &Runner{Exec: runner, UI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false)), DepsUI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "does-not-exist.yml"},
	})
	assertAnsibleDenied(t, err, runner.Calls)
}

// ---- RunPlaybook: ansible отсутствует -------------------------------------

func TestRunPlaybook_AnsibleMissing_AutoYesFalse_ErrorWithRecipe(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	runner := execx.NewRecordingRunner()
	runner.SetLookPath("brew", "/opt/homebrew/bin/brew")
	// ansible-playbook НЕ в PATH; AutoYes=false — установка не подтверждается.

	r := &Runner{Exec: runner, UI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false)), DepsUI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
		AutoYes:     false,
	})
	assertAnsibleDenied(t, err, runner.Calls)
}

func TestRunPlaybook_AnsibleMissing_AutoYesTrue_InstallsThenRechecks(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	inner := execx.NewRecordingRunner()
	inner.SetLookPath("brew", "/opt/homebrew/bin/brew")
	inner.On("brew", []string{"install", "ansible"}, execx.Response{Result: execx.Result{Stdout: "==> Installing ansible\n"}})
	inner.OnCommand("ansible-playbook", execx.Response{Result: execx.Result{Stdout: "PLAY [setup]\n"}})

	// ansible-playbook найден только со второй проверки LookPath (первая —
	// до установки, вторая — после): имитирует появление бинарника в PATH
	// сразу после `brew install ansible`.
	errNotFound := errors.New("ansible-playbook: не найден в PATH")
	runner := &sequencedLookupRunner{RecordingRunner: inner, name: "ansible-playbook", seq: []error{
		errNotFound,
		nil,
	}}

	var out bytes.Buffer
	r := &Runner{Exec: runner, UI: deps.NewUI(&out, ui.NewPalette(false)), DepsUI: deps.NewUI(&out, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
		AutoYes:     true,
	})
	assertAnsibleDenied(t, err, inner.Calls)
}

func TestRunPlaybook_AnsibleAlreadyPresent_NoInstallAttempted(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible-playbook", "/usr/local/bin/ansible-playbook")
	runner.OnCommand("ansible-playbook", execx.Response{Result: execx.Result{}})

	r := &Runner{Exec: runner, UI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false)), DepsUI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
		AutoYes:     false,
	})
	assertAnsibleDenied(t, err, runner.Calls)
}

// ---- RunPlaybook: exit-код пробрасывается ---------------------------------

func TestRunPlaybook_ExitCodePropagates(t *testing.T) {
	dir := t.TempDir()
	writePlaybookFixture(t, dir)

	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible-playbook", "/usr/local/bin/ansible-playbook")
	exitErr := &execx.ExitError{Name: "ansible-playbook", ExitCode: 2, Stderr: "fatal: [localhost]: FAILED!"}
	runner.OnCommand("ansible-playbook", execx.Response{Result: execx.Result{ExitCode: 2}, Err: exitErr})

	r := &Runner{Exec: runner, UI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false)), DepsUI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false))}

	err := r.RunPlaybook(context.Background(), Options{
		TemplateDir: dir,
		ProjectRoot: "/root",
		Playbook:    manifest.Playbook{Name: "setup", File: "setup.yml"},
	})
	assertAnsibleDenied(t, err, runner.Calls)
}

func assertAnsibleDenied(t *testing.T, err error, calls []execx.Call) {
	t.Helper()
	if !errors.Is(err, ErrAnsibleAdapterUnavailable) {
		t.Fatalf("RunPlaybook = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("runner calls = %+v", calls)
	}
}

// ---- NewRunner -------------------------------------------------------------

func TestNewRunner_SharesUIAndDepsUI(t *testing.T) {
	var buf bytes.Buffer
	r := NewRunner(execx.NewRecordingRunner(), &buf, ui.NewPalette(false))
	if r.Exec == nil {
		t.Error("Exec = nil")
	}
	r.UI.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("buf = %q, want сообщение через UI.Info попавшим в общий writer", buf.String())
	}
	r.DepsUI.Warn("world")
	if !strings.Contains(buf.String(), "world") {
		t.Errorf("buf = %q, want сообщение через DepsUI.Warn в том же writer, что UI", buf.String())
	}
}

// ---- helpers ---------------------------------------------------------------

// writePlaybookFixture создаёт минимальный (пустой список tasks) валидный по
// форме ansible-плейбук setup.yml в dir — содержимое не важно, RunPlaybook не
// парсит YAML сам (это делает ansible-playbook, замоканный в тестах).
func writePlaybookFixture(t *testing.T, dir string) {
	t.Helper()
	const name = "setup.yml"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("---\n- hosts: localhost\n  tasks: []\n"), 0o644); err != nil {
		t.Fatalf("write playbook fixture %s: %v", name, err)
	}
}

// sequencedLookupRunner — Runner-обёртка, дающая полный контроль над
// последовательными ответами LookPath(name) — нужен, чтобы протестировать
// повторную проверку [ensureAnsiblePlaybook] после попытки установки: реальный
// os/exec.LookPath увидел бы бинарник, появившийся в PATH после `brew
// install`, но execx.RecordingRunner.LookPath статичен (не меняется по ходу
// теста) — эта обёртка имитирует "появление после установки" явной
// последовательностью ответов.
type sequencedLookupRunner struct {
	*execx.RecordingRunner
	name  string
	seq   []error
	calls int
}

func (r *sequencedLookupRunner) LookPath(name string) (string, error) {
	if name != r.name {
		return r.RecordingRunner.LookPath(name)
	}
	idx := r.calls
	if idx >= len(r.seq) {
		idx = len(r.seq) - 1
	}
	r.calls++
	if r.seq[idx] == nil {
		return "/usr/local/bin/" + name, nil
	}
	return "", r.seq[idx]
}

func containsBrewInstall(calls []execx.Call) bool {
	for _, c := range calls {
		if c.Name == "brew" && len(c.Args) == 2 && c.Args[0] == "install" && c.Args[1] == "ansible" {
			return true
		}
	}
	return false
}

type denialSpy struct{ lookups, runs int }

func (s *denialSpy) LookPath(string) (string, error) {
	s.lookups++
	return "", errors.New("LOOKUP_CANARY")
}
func (s *denialSpy) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	s.runs++
	return execx.Result{}, errors.New("RUN_CANARY")
}

func TestAnsibleDeniedBeforeAnyRunnerOrPathEffect(t *testing.T) {
	for _, autoYes := range []bool{false, true} {
		t.Run("auto", func(t *testing.T) {
			spy := &denialSpy{}
			var out bytes.Buffer
			r := &Runner{Exec: spy, UI: deps.NewUI(&out, ui.NewPalette(false)), DepsUI: deps.NewUI(&out, ui.NewPalette(false))}
			hostile := "/tmp/LOOKUP_CANARY/../../secret.yml"
			err := r.RunPlaybook(context.Background(), Options{TemplateDir: hostile, ProjectRoot: hostile, Playbook: manifest.Playbook{Name: "RUN_CANARY", File: hostile}, AutoYes: autoYes})
			if !errors.Is(err, ErrAnsibleAdapterUnavailable) || spy.lookups != 0 || spy.runs != 0 || out.Len() != 0 || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("unsafe denial err=%v lookup=%d run=%d out=%q", err, spy.lookups, spy.runs, out.String())
			}
			if err := ensureAnsiblePlaybook(context.Background(), spy, r.DepsUI, autoYes); !errors.Is(err, ErrAnsibleAdapterUnavailable) || spy.lookups != 0 || spy.runs != 0 {
				t.Fatal("helper touched runner")
			}
			if err := ensureAnsiblePlaybook(context.Background(), nil, r.DepsUI, autoYes); !errors.Is(err, ErrAnsibleAdapterUnavailable) {
				t.Fatal("nil helper unsafe")
			}
		})
	}
}

func TestAnsibleDenialLeavesSyntheticRootsUnchanged(t *testing.T) {
	root := t.TempDir()
	home, tmp, project := filepath.Join(root, "home"), filepath.Join(root, "tmp"), filepath.Join(root, "project")
	for _, p := range []string{home, tmp, project} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(project, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", tmp)
	before := snapshotDenialRoots(t, home, tmp, project)
	spy := &denialSpy{}
	r := &Runner{Exec: spy, UI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false)), DepsUI: deps.NewUI(&bytes.Buffer{}, ui.NewPalette(false))}
	if err := r.RunPlaybook(context.Background(), Options{TemplateDir: project, ProjectRoot: project, Playbook: manifest.Playbook{File: "hostile.yml"}, AutoYes: true}); !errors.Is(err, ErrAnsibleAdapterUnavailable) {
		t.Fatal(err)
	}
	if err := ensureAnsiblePlaybook(context.Background(), nil, r.DepsUI, true); !errors.Is(err, ErrAnsibleAdapterUnavailable) {
		t.Fatal(err)
	}
	if after := snapshotDenialRoots(t, home, tmp, project); after != before || spy.lookups != 0 || spy.runs != 0 {
		t.Fatalf("denial mutated roots before=%q after=%q", before, after)
	}
}
func snapshotDenialRoots(t *testing.T, roots ...string) string {
	t.Helper()
	var b strings.Builder
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(root)
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(e.Name() + info.Mode().String())
			if !e.IsDir() {
				raw, err := os.ReadFile(filepath.Join(root, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				b.Write(raw)
			}
		}
	}
	return b.String()
}
