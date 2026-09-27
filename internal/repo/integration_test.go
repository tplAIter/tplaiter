package repo

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
)

// gitExec — реальный git-раннер для построения тестовых репозиториев (через
// internal/execx, а не прямой os/exec — depguard).
var gitExec = execx.Exec{}

// requireGit пропускает тест, если git недоступен (например, в урезанном CI).
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — интеграционный тест пропущен")
	}
}

// gitEnv — детерминированное окружение git для коммитов без глобального конфига
// (дополняет os.Environ() внутри execx).
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// initOrigin создаёт «удалённый» репозиторий в новом каталоге с веткой main и
// включённым partial-clone (uploadpack.allowFilter) для --filter=blob:none.
func initOrigin(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init", "-b", "main")
	runGit(t, dir, "config", "uploadpack.allowFilter", "true")
	return dir
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", msg)
}

func fileURL(dir string) string { return "file://" + dir }

const singleManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: go-service
  version: "1.1.0"
  description: "Go service"
  labels:
    lang: [go]
    infra: [kafka]
`

// newIntegrationManager строит менеджер с реальным git и изолированным home/стором.
func newIntegrationManager(t *testing.T) *Manager {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	st, err := auth.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	u := UI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Interactive: false}
	return New(home, execx.Exec{}, st, u)
}

func TestIntegration_SingleRepoLifecycle(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1.0.0\n")
	commitAll(t, origin, "init")
	runGit(t, origin, "tag", "v1.0.0")
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1.1.0\n")
	commitAll(t, origin, "bump")
	runGit(t, origin, "tag", "v1.1.0")

	m := newIntegrationManager(t)

	if err := m.Add(ctx, AddOptions{Alias: "example", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// List: один репозиторий, один шаблон, тип git (file://).
	infos, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 1 || infos[0].Ref.Alias != "example" || infos[0].Templates != 1 {
		t.Fatalf("List = %+v", infos)
	}
	if infos[0].Ref.Type != state.RepoKindGit {
		t.Errorf("тип = %q, want git", infos[0].Ref.Type)
	}

	// Индекс: два стабильных тега, старший — v1.1.0.
	res, err := m.ResolveRef("go-service")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if res.Version != "v1.1.0" || res.GitRef != "v1.1.0" {
		t.Errorf("resolve default = %+v, want v1.1.0", res)
	}

	// Checkout на старый тег даёт содержимое той версии.
	assertCheckout(ctx, t, m, "example", "v1.0.0", ".", "hello.txt", "v1.0.0\n")

	// Update: добавляем тег на удалённой стороне, fetch должен его увидеть.
	runGit(t, origin, "tag", "v1.2.0")
	if err := m.Update(ctx, "example"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	res, err = m.ResolveRef("go-service")
	if err != nil {
		t.Fatalf("ResolveRef после update: %v", err)
	}
	if res.Version != "v1.2.0" {
		t.Errorf("после update старший тег = %q, want v1.2.0", res.Version)
	}

	// Remove: конфиг, индекс и клон исчезают.
	if err := m.Remove("example"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	infos, _ = m.List()
	if len(infos) != 0 {
		t.Errorf("после Remove List = %+v", infos)
	}
	if _, err := os.Stat(m.cloneDir("example")); !os.IsNotExist(err) {
		t.Errorf("клон не удалён: %v", err)
	}
}

func TestIntegration_MultiRepo(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, repoManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Repository
metadata:
  name: example-templates
templates:
  - path: alpha/
  - path: beta/
`)
	writeFile(t, filepath.Join(origin, "alpha", templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: alpha
  version: "0.1.0"
  description: "Alpha"
`)
	writeFile(t, filepath.Join(origin, "alpha", "marker.txt"), "alpha-v0.1.0\n")
	writeFile(t, filepath.Join(origin, "beta", templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: beta
  version: "0.2.0"
  description: "Beta"
`)
	commitAll(t, origin, "init")
	runGit(t, origin, "tag", "alpha/v0.1.0")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "example", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	infos, _ := m.List()
	if len(infos) != 1 || infos[0].Templates != 2 {
		t.Fatalf("List = %+v, want 2 шаблона", infos)
	}

	// alpha имеет namespaced-тег alpha/v0.1.0.
	res, err := m.ResolveRef("example/alpha")
	if err != nil {
		t.Fatalf("ResolveRef alpha: %v", err)
	}
	if res.GitRef != "alpha/v0.1.0" || res.Version != "v0.1.0" {
		t.Errorf("alpha resolve = %+v", res)
	}
	// beta без тегов → latest на ветке.
	resB, err := m.ResolveRef("example/beta")
	if err != nil {
		t.Fatalf("ResolveRef beta: %v", err)
	}
	if resB.Version != "latest" {
		t.Errorf("beta resolve = %+v, want latest", resB)
	}

	// Checkout alpha на теге даёт нужный подкаталог.
	assertCheckout(ctx, t, m, "example", "alpha/v0.1.0", "alpha", "marker.txt", "alpha-v0.1.0\n")
}

func TestIntegration_AutoScanNoRepoManifest(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	// Нет repo.manifest.yaml в корне — авто-скан */template.manifest.yaml.
	writeFile(t, filepath.Join(origin, "svc-a", templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc-a
  version: "1.0.0"
`)
	// Глубина 2: group/svc-b/template.manifest.yaml
	writeFile(t, filepath.Join(origin, "group", "svc-b", templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc-b
  version: "1.0.0"
`)
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "auto", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	infos, _ := m.List()
	if len(infos) != 1 || infos[0].Templates != 2 {
		t.Fatalf("авто-скан нашёл не 2 шаблона: %+v", infos)
	}
	if _, err := m.ResolveRef("svc-b"); err != nil {
		t.Errorf("ResolveRef svc-b (глубина 2): %v", err)
	}
}

func TestIntegration_BrokenManifestFailsAdd(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	// Манифест без обязательных полей metadata.name/version → Validate падает.
	writeFile(t, filepath.Join(origin, templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  description: "без имени и версии"
`)
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	err := m.Add(ctx, AddOptions{Alias: "bad", URL: fileURL(origin)})
	if err == nil {
		t.Fatal("Add должен упасть на битом манифесте")
	}
	if !strings.Contains(err.Error(), templateManifestName) {
		t.Errorf("ошибка без пути к манифесту: %v", err)
	}
	// Репозиторий НЕ зарегистрирован, клон удалён.
	infos, _ := m.List()
	if len(infos) != 0 {
		t.Errorf("битый репозиторий зарегистрирован: %+v", infos)
	}
	if _, statErr := os.Stat(m.cloneDir("bad")); !os.IsNotExist(statErr) {
		t.Errorf("клон битого репозитория не удалён")
	}
}

// assertCheckout проверяет, что Checkout(alias, ref, templatePath) отдаёт fs.FS,
// в котором файл wantFile содержит wantContent.
func assertCheckout(ctx context.Context, t *testing.T, m *Manager, alias, ref, templatePath, wantFile, wantContent string) {
	t.Helper()
	fsys, cleanup, err := m.Checkout(ctx, alias, ref, templatePath)
	if err != nil {
		t.Fatalf("Checkout %s@%s: %v", alias, ref, err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	}()

	data, err := fs.ReadFile(fsys, wantFile)
	if err != nil {
		t.Fatalf("чтение %s: %v", wantFile, err)
	}
	if string(data) != wantContent {
		t.Errorf("%s = %q, want %q", wantFile, string(data), wantContent)
	}
}
