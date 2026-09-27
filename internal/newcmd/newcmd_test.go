package newcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// --- инфраструктура: реальный git-репозиторий file:// (как в internal/repo) ---

var gitExec = execx.Exec{}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — интеграционный тест пропущен")
	}
}

func gitEnv() []string {
	return []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: gitEnv()})
	if err != nil {
		t.Fatalf("git %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
}

// initOriginFromDir создаёт «удалённый» git-репозиторий, скопировав дерево
// srcDir в его корень, и тегирует v1.0.0.
func initOriginFromDir(t *testing.T, srcDir string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTreeOnDisk(t, srcDir, origin)
	runGit(t, origin, "init", "-b", "main")
	runGit(t, origin, "config", "uploadpack.allowFilter", "true")
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-m", "init")
	runGit(t, origin, "tag", "v1.0.0")
	return origin
}

// initOriginFromFiles создаёт origin из карты относительный-путь→содержимое.
func initOriginFromFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	for rel, content := range files {
		p := filepath.Join(origin, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, origin, "init", "-b", "main")
	runGit(t, origin, "config", "uploadpack.allowFilter", "true")
	runGit(t, origin, "add", "-A")
	runGit(t, origin, "commit", "-m", "init")
	runGit(t, origin, "tag", "v1.0.0")
	return origin
}

func copyTreeOnDisk(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if merr := os.MkdirAll(filepath.Dir(target), 0o755); merr != nil {
			return merr
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTreeOnDisk: %v", err)
	}
}

func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "fixtures")
}

// newManager строит repo.Manager с реальным git и изолированным home.
func newManager(t *testing.T, home string) *repo.Manager {
	t.Helper()
	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := repo.UI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Interactive: false}
	return repo.New(home, gitExec, st, u)
}

// setupSingleBasic поднимает home + репозиторий example с шаблоном single-basic и
// возвращает менеджер и home.
func setupSingleBasic(t *testing.T) (*repo.Manager, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initOriginFromDir(t, filepath.Join(fixturesRoot(t), "single-basic"))
	mgr := newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return mgr, home
}

func newTestDeps(mgr *repo.Manager, home string, out, errOut *bytes.Buffer) Deps {
	return Deps{
		Manager:  mgr,
		Runner:   execx.Exec{},
		Home:     home,
		Prompter: &survey.ScriptedPrompter{},
		Out:      out,
		Err:      errOut,
		Palette:  ui.NewPalette(false),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

// --- e2e: неинтерактивный путь ---

func TestRun_E2E_NonInteractive(t *testing.T) {
	if err := Run(context.Background(), Options{ProjectName: "invalid***", Dir: filepath.Join(t.TempDir(), "target")}, Deps{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("legacy Run error = %v", err)
	}
}

// --- интерактивный путь через ScriptedPrompter ---

func TestRun_Interactive_Scripted(t *testing.T) {
	if err := Run(context.Background(), Options{ProjectName: "interactive", Dir: filepath.Join(t.TempDir(), "target"), Interactive: true}, Deps{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("legacy Run error = %v", err)
	}
}

// --- повторный new → ошибка, существующий каталог не тронут ---

func TestRun_RepeatIntoNonEmpty_Errors(t *testing.T) {
	requireGit(t)
	mgr, home := setupSingleBasic(t)
	target := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	opts := Options{
		Ref: "example/single-basic", ProjectName: "svc", Dir: target,
		Defaults: true, CLIVersion: "v1.0.0",
	}
	err := Run(context.Background(), opts, newTestDeps(mgr, home, &out, &errOut))
	if err == nil {
		t.Fatalf("ожидалась ошибка при непустом каталоге")
	}
	// Существующий файл не тронут (каталог не удалён).
	mustExist(t, sentinel)
}

// --- провал обязательного hook → каталог удалён ---

func TestRun_RequiredHookFails_RemovesTarget(t *testing.T) {
	requireGit(t)
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initOriginFromFiles(t, map[string]string{
		"template.manifest.yaml": minimalManifest(">=0.1.0", "  postCreate:\n    - run: \"exit 3\"\n"),
		"files/main.txt.tmpl":    "hello {{ .Project.Slug }}\n",
	})
	mgr := newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	target := filepath.Join(t.TempDir(), "proj")
	var out, errOut bytes.Buffer
	opts := Options{
		Ref: "example/svc", ProjectName: "svc", Dir: target,
		Defaults: true, CLIVersion: "v1.0.0",
	}
	err := Run(context.Background(), opts, newTestDeps(mgr, home, &out, &errOut))
	if err == nil {
		t.Fatalf("ожидалась ошибка провалившегося hook")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("каталог не удалён после провала hook: %v", statErr)
	}
	// Проект не зарегистрирован.
	projects, _ := state.LoadProjects(home)
	if len(projects.Items) != 0 {
		t.Errorf("проект зарегистрирован несмотря на провал: %+v", projects.Items)
	}
}

// --- --no-hooks: hook не выполняется ---

func TestRun_NoHooks(t *testing.T) {
	if err := Run(context.Background(), Options{ProjectName: "nohooks", Dir: filepath.Join(t.TempDir(), "target"), NoHooks: true}, Deps{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("legacy Run error = %v", err)
	}
}

// --- версия-гейт requires.tplaiter ---

func TestRun_VersionGate(t *testing.T) {
	if err := Run(context.Background(), Options{ProjectName: "version", Dir: filepath.Join(t.TempDir(), "target")}, Deps{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("legacy Run error = %v", err)
	}
}

// --- неинтерактивный режим с обязательной строковой настройкой без preset ---

func TestRun_MissingRequiredString_NonInteractive(t *testing.T) {
	if err := Run(context.Background(), Options{ProjectName: "required", Dir: filepath.Join(t.TempDir(), "target")}, Deps{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("legacy Run error = %v", err)
	}
}

// --- copyResources ---

func TestCopyResources_Declared(t *testing.T) {
	src := fstest.MapFS{
		"environment/setup.yml":        {Data: []byte("play")},
		"environment/vars/db.yml":      {Data: []byte("vars")},
		"generators/use-case.go.tmpl":  {Data: []byte("snippet")},
		"generators/uc.anchor.tmpl":    {Data: []byte("anchor")},
		"ai-config/config.json":        {Data: []byte("{}")},
		"ai-config/modules/00-base.md": {Data: []byte("base")},
	}
	tpl := &manifest.Template{
		Environment: manifest.Environment{Playbooks: []manifest.Playbook{{Name: "setup", File: "environment/setup.yml"}}},
		Generators: []manifest.Generator{{
			Kind: "use-case", Snippet: "generators/use-case.go.tmpl",
			Anchors: []manifest.Anchor{{File: "internal/app.go", Anchor: "//X", Insert: "generators/uc.anchor.tmpl"}},
		}},
		AIConfig: manifest.AIConfig{Path: "ai-config"},
	}

	target := t.TempDir()
	if err := copyResources(src, target, tpl); err != nil {
		t.Fatalf("copyResources: %v", err)
	}
	// environment/generators — с сохранением структуры под RelPath.
	mustExist(t, filepath.Join(target, ".tplaiter", "environment", "environment", "setup.yml"))
	mustExist(t, filepath.Join(target, ".tplaiter", "environment", "environment", "vars", "db.yml"))
	mustExist(t, filepath.Join(target, ".tplaiter", "generators", "generators", "use-case.go.tmpl"))
	mustExist(t, filepath.Join(target, ".tplaiter", "generators", "generators", "uc.anchor.tmpl"))
	// ai-config — содержимое каталога напрямую в RelPath.
	mustExist(t, filepath.Join(target, ".tplaiter", "ai-config", "config.json"))
	mustExist(t, filepath.Join(target, ".tplaiter", "ai-config", "modules", "00-base.md"))
}

func TestCopyResources_None(t *testing.T) {
	src := fstest.MapFS{"files/main.txt": {Data: []byte("x")}}
	tpl := &manifest.Template{}
	target := t.TempDir()
	if err := copyResources(src, target, tpl); err != nil {
		t.Fatalf("copyResources: %v", err)
	}
	for _, sub := range []string{"environment", "generators", "ai-config"} {
		p := filepath.Join(target, ".tplaiter", sub)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("недекларированный ресурс создан: %s (%v)", p, err)
		}
	}
}

// --- slug / версия / uuid юниты ---

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"demo_svc":       "demo_svc",
		"Demo Svc":       "demo_svc",
		"my-cool-thing":  "my_cool_thing",
		"Order  Service": "order_service",
	}
	for in, want := range cases {
		got, err := Slugify(in)
		if err != nil {
			t.Errorf("Slugify(%q) ошибка: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Slugify(%q) = %q, ожидался %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "  ", "1abc", "_leading", "нельзя"} {
		if _, err := Slugify(bad); err == nil {
			t.Errorf("Slugify(%q) должен был вернуть ошибку", bad)
		}
	}
}

func TestCheckTplaterVersion(t *testing.T) {
	if err := checkTplaterVersion(">=0.1.0", "v1.0.0"); err != nil {
		t.Errorf("удовлетворяющая версия: %v", err)
	}
	if err := checkTplaterVersion(">=99.0.0", "v1.0.0"); err == nil {
		t.Errorf("несовместимая версия должна была провалиться")
	}
	// dev-сборка проходит любой гейт.
	if err := checkTplaterVersion(">=99.0.0", "dev"); err != nil {
		t.Errorf("dev должен проходить гейт: %v", err)
	}
	if err := checkTplaterVersion("", "dev"); err != nil {
		t.Errorf("пустой constraint: %v", err)
	}
}

func TestNewUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newUUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			t.Fatalf("некорректный формат uuid: %q", id)
		}
		if seen[id] {
			t.Fatalf("повтор uuid: %q", id)
		}
		seen[id] = true
	}
}

// --- helpers ---

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("ожидался файл %s: %v", path, err)
	}
}

func assertValidBaseline(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baseline read: %v", err)
	}
	var b struct {
		Schema int               `json:"schema"`
		Files  map[string]string `json:"files"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("baseline json: %v", err)
	}
	if b.Schema == 0 || len(b.Files) == 0 {
		t.Errorf("baseline пуст/невалиден: %+v", b)
	}
}

// minimalManifest собирает минимальный манифест шаблона svc с заданным
// требованием tplater и (опционально) блоком hooks.postCreate.
func minimalManifest(tplaterReq, hooksBlock string) string {
	m := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: 0.1.0
engine:
  root: files
requires:
  tplater: "` + tplaterReq + `"
`
	if hooksBlock != "" {
		m += "hooks:\n" + hooksBlock
	}
	return m
}
