package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
)

// Хелперы построения локального git-репозитория для тестов — минимальный
// дубликат internal/repo/integration_test.go (его хелперы непубличны своему
// пакету, а cmd-тестам нужен ровно тот же приём: file://-репо без сети).

var templateGitExec = execx.Exec{}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := templateGitExec.LookPath("git"); err != nil {
		t.Skip("git не найден в PATH — тест пропущен")
	}
}

func gitEnvForTemplateTests() []string {
	return []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func runGitForTemplateTests(t *testing.T, dir string, args ...string) {
	t.Helper()
	res, err := templateGitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: gitEnvForTemplateTests()})
	if err != nil {
		t.Fatalf("git %s: %v\n%s%s", strings.Join(args, " "), err, res.Stdout, res.Stderr)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func initTemplateOrigin(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGitForTemplateTests(t, dir, "init", "-b", "main")
	runGitForTemplateTests(t, dir, "config", "uploadpack.allowFilter", "true")
	return dir
}

func commitAllForTemplateTests(t *testing.T, dir string) {
	t.Helper()
	runGitForTemplateTests(t, dir, "add", "-A")
	runGitForTemplateTests(t, dir, "commit", "-m", "init")
}

func templateFileURL(dir string) string { return "file://" + dir }

// newTemplateTestManager создаёт repo.Manager с реальным git и изолированным
// home/стором (TPLAITER_HOME переопределён на t.TempDir()) — тем же
// экземпляром, каким `tplater repo add` пользуется в проде, но напрямую (без
// прогона через cobra), чтобы фикстуры собирались быстрее.
func newTemplateTestManager(t *testing.T) *repo.Manager {
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

	u := repo.UI{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Interactive: false}
	return repo.New(home, execx.Exec{}, st, u)
}

// runTemplateCmd исполняет свежесобранное дерево команд `template` (по
// образцу runRunCmd/runAuth в соседних тестах этого пакета) и возвращает
// stdout+stderr вместе.
func runTemplateCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := newTemplateCmd()
	var out, errBuf bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errBuf)
	c.SetArgs(args)
	err := c.Execute()
	return out.String() + errBuf.String(), err
}

const alphaManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: alpha
  displayName: "Alpha Service"
  version: "1.0.0"
  description: "Demo alpha template"
  maintainers:
    - name: "Alice"
      email: "alice@example.com"
  labels:
    lang: [go]
    infra: [kafka]
  docs: README.md
settings:
  - group: framework
    title: "Framework"
    type: select
    default: gin
    options:
      - id: gin
        title: "Gin"
      - id: echo
        title: "Echo"
      - id: fiber
        title: "Fiber"
        status: planned
        settings:
          - group: fiberMode
            title: "Fiber mode"
            type: select
            default: standalone
            options:
              - id: standalone
                title: "Standalone"
              - id: cluster
                title: "Cluster"
commands:
  build:
    run: "go build ./..."
    description: "Собрать бинарь"
`

const alphaReadme = "# Alpha Service\n\nSome **docs** content for alpha.\n"

const alphaMainGo = "package main\n"

// newAlphaOrigin строит origin-репозиторий с одним (single) шаблоном alpha:
// манифест + README.md (docs) + files/main.go, коммит и тег v1.0.0.
func newAlphaOrigin(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "template.manifest.yaml"), alphaManifest)
	writeTestFile(t, filepath.Join(origin, "README.md"), alphaReadme)
	writeTestFile(t, filepath.Join(origin, "files", "main.go"), alphaMainGo)
	commitAllForTemplateTests(t, origin)
	runGitForTemplateTests(t, origin, "tag", "v1.0.0")
	return origin
}

const betaGammaRepoManifest = `apiVersion: tplater.dev/v1alpha1
kind: Repository
metadata:
  name: bg-templates
templates:
  - path: beta/
  - path: gamma/
`

const betaManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: beta
  version: "0.1.0"
  description: "Beta template"
  labels:
    lang: [python]
`

const gammaManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: gamma
  version: "0.2.0"
  description: "Gamma template"
  labels:
    lang: [go]
    infra: [kafka, postgres]
`

// newBetaGammaOrigin строит multi-репо origin с шаблонами beta (python) и
// gamma (go/kafka+postgres) — для тестов фильтров `template list`.
func newBetaGammaOrigin(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "repo.manifest.yaml"), betaGammaRepoManifest)
	writeTestFile(t, filepath.Join(origin, "beta", "template.manifest.yaml"), betaManifest)
	writeTestFile(t, filepath.Join(origin, "gamma", "template.manifest.yaml"), gammaManifest)
	commitAllForTemplateTests(t, origin)
	return origin
}

func TestTemplateList_NoFilters(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "b", URL: templateFileURL(newBetaGammaOrigin(t))}); err != nil {
		t.Fatalf("Add b: %v", err)
	}

	out, err := runTemplateCmd(t, "list")
	if err != nil {
		t.Fatalf("template list: %v\n%s", err, out)
	}
	for _, want := range []string{"alpha", "beta", "gamma", "a", "b"} {
		if !strings.Contains(out, want) {
			t.Errorf("вывод не содержит %q:\n%s", want, out)
		}
	}
}

func TestTemplateList_RepoFilter(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "b", URL: templateFileURL(newBetaGammaOrigin(t))}); err != nil {
		t.Fatalf("Add b: %v", err)
	}

	out, err := runTemplateCmd(t, "list", "--repo", "b")
	if err != nil {
		t.Fatalf("template list --repo b: %v\n%s", err, out)
	}
	if strings.Contains(out, "alpha") {
		t.Errorf("--repo b не должен показывать alpha:\n%s", out)
	}
	if !strings.Contains(out, "beta") || !strings.Contains(out, "gamma") {
		t.Errorf("--repo b должен показывать beta и gamma:\n%s", out)
	}
}

func TestTemplateList_NameFilter(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "b", URL: templateFileURL(newBetaGammaOrigin(t))}); err != nil {
		t.Fatalf("Add b: %v", err)
	}

	// Регистр не должен иметь значения.
	out, err := runTemplateCmd(t, "list", "--name", "GAM")
	if err != nil {
		t.Fatalf("template list --name GAM: %v\n%s", err, out)
	}
	if !strings.Contains(out, "gamma") {
		t.Errorf("--name GAM должен показывать gamma:\n%s", out)
	}
	if strings.Contains(out, "alpha") || strings.Contains(out, "beta") {
		t.Errorf("--name GAM не должен показывать alpha/beta:\n%s", out)
	}
}

func TestTemplateList_LabelFiltersAND(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "b", URL: templateFileURL(newBetaGammaOrigin(t))}); err != nil {
		t.Fatalf("Add b: %v", err)
	}

	// lang=go И infra=kafka — подходят alpha (lang=go,infra=kafka) и gamma
	// (lang=go,infra=kafka,postgres); beta (python) — нет.
	out, err := runTemplateCmd(t, "list", "-l", "lang=go", "-l", "infra=kafka")
	if err != nil {
		t.Fatalf("template list -l lang=go -l infra=kafka: %v\n%s", err, out)
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "gamma") {
		t.Errorf("ожидались alpha и gamma:\n%s", out)
	}
	if strings.Contains(out, "beta") {
		t.Errorf("beta (python) не должна пройти фильтр lang=go:\n%s", out)
	}

	// lang=go И infra=postgres — только gamma (у alpha нет postgres).
	out, err = runTemplateCmd(t, "list", "-l", "lang=go", "-l", "infra=postgres")
	if err != nil {
		t.Fatalf("template list -l lang=go -l infra=postgres: %v\n%s", err, out)
	}
	if strings.Contains(out, "alpha") {
		t.Errorf("alpha не имеет infra=postgres, не должна пройти AND-фильтр:\n%s", out)
	}
	if !strings.Contains(out, "gamma") {
		t.Errorf("ожидалась gamma:\n%s", out)
	}
}

func TestTemplateList_EmptyByFilter(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}

	out, err := runTemplateCmd(t, "list", "--name", "не-существует-такого-имени")
	if err != nil {
		t.Fatalf("template list --name <нет>: %v\n%s", err, out)
	}
	if !strings.Contains(out, "не подходит по заданным фильтрам") {
		t.Errorf("ожидалось дружелюбное сообщение о пустом результате фильтра:\n%s", out)
	}
}

func TestTemplateList_EmptyNoRepos(t *testing.T) {
	newTemplateTestManager(t) // только готовит изолированный home, репозитории не добавляет.

	out, err := runTemplateCmd(t, "list")
	if err != nil {
		t.Fatalf("template list (без репозиториев): %v\n%s", err, out)
	}
	if !strings.Contains(out, "repo add") {
		t.Errorf("ожидалась подсказка `repo add` при полном отсутствии репозиториев:\n%s", out)
	}
}

func TestTemplateShow_HeaderSettingsDocs(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)
	t.Setenv("NO_COLOR", "1")

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}

	out, err := runTemplateCmd(t, "show", "a/alpha")
	if err != nil {
		t.Fatalf("template show a/alpha: %v\n%s", err, out)
	}

	// Шапка: displayName(name), репозиторий, версия+доступные версии,
	// описание, maintainers, labels.
	for _, want := range []string{
		"Alpha Service (alpha)",
		"репозиторий: a",
		"версия:      v1.0.0",
		"доступны: v1.0.0",
		"описание:    Demo alpha template",
		"maintainers: Alice <alice@example.com>",
		"labels:      infra=kafka; lang=go",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("шапка не содержит %q:\n%s", want, out)
		}
	}

	// Дерево настроек: группа верхнего уровня, вложенная группа с бОльшим
	// отступом, planned-опция помечена.
	if !strings.Contains(out, "- framework — Framework [select, default=gin]") {
		t.Errorf("нет строки группы framework:\n%s", out)
	}
	if !strings.Contains(out, "* fiber — Fiber [planned]") {
		t.Errorf("planned-опция fiber не помечена:\n%s", out)
	}
	if !strings.Contains(out, "- fiberMode — Fiber mode [select, default=standalone]") {
		t.Errorf("нет вложенной группы fiberMode:\n%s", out)
	}
	// Вложенная группа должна иметь больший отступ, чем framework.
	frIdx := strings.Index(out, "- framework")
	fmIdx := strings.Index(out, "- fiberMode")
	if frIdx < 0 || fmIdx < 0 || fmIdx < frIdx {
		t.Fatalf("не удалось найти обе группы в ожидаемом порядке:\n%s", out)
	}
	frIndent := frIdx - strings.LastIndex(out[:frIdx], "\n") - 1
	fmIndent := fmIdx - strings.LastIndex(out[:fmIdx], "\n") - 1
	if fmIndent <= frIndent {
		t.Errorf("вложенная группа fiberMode (отступ %d) не глубже framework (отступ %d)", fmIndent, frIndent)
	}

	// Команды.
	if !strings.Contains(out, "build") || !strings.Contains(out, "Собрать бинарь") {
		t.Errorf("нет команды build в выводе:\n%s", out)
	}

	// Docs: NO_COLOR=1 -> текст README как есть, без glamour-разметки.
	if !strings.Contains(out, "# Alpha Service") || !strings.Contains(out, "Some **docs** content for alpha.") {
		t.Errorf("docs не выведены как plain-текст:\n%s", out)
	}
}

func TestTemplateShow_Ambiguous(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "c", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add c: %v", err)
	}

	out, err := runTemplateCmd(t, "show", "alpha")
	if err == nil {
		t.Fatalf("ожидалась ошибка неоднозначности, вывод:\n%s", out)
	}
	msg := err.Error()
	if !strings.Contains(msg, "неоднозначно") {
		t.Errorf("сообщение об ошибке не упоминает неоднозначность: %v", err)
	}
	if !strings.Contains(msg, "a/alpha") || !strings.Contains(msg, "c/alpha") {
		t.Errorf("сообщение об ошибке не перечисляет обоих кандидатов: %v", err)
	}
}

func TestTemplatePull_CopiesTreeAndRejectsNonEmptyDest(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	out, err := runTemplateCmd(t, "pull", "a/alpha", "--dest", dest)
	if err != nil {
		t.Fatalf("template pull: %v\n%s", err, out)
	}
	if !strings.Contains(out, "alpha@v1.0.0") || !strings.Contains(out, dest) {
		t.Errorf("сообщение об успешной выгрузке неожиданное: %q", out)
	}

	gotManifest, err := os.ReadFile(filepath.Join(dest, "template.manifest.yaml"))
	if err != nil {
		t.Fatalf("template.manifest.yaml не выгружен: %v", err)
	}
	if string(gotManifest) != alphaManifest {
		t.Errorf("template.manifest.yaml содержимое не совпадает")
	}
	gotReadme, err := os.ReadFile(filepath.Join(dest, "README.md"))
	if err != nil {
		t.Fatalf("README.md не выгружен: %v", err)
	}
	if string(gotReadme) != alphaReadme {
		t.Errorf("README.md содержимое не совпадает")
	}
	gotMain, err := os.ReadFile(filepath.Join(dest, "files", "main.go"))
	if err != nil {
		t.Fatalf("files/main.go не выгружен: %v", err)
	}
	if string(gotMain) != alphaMainGo {
		t.Errorf("files/main.go содержимое не совпадает")
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Errorf(".git worktree-артефакт не должен попадать в выгрузку (err=%v)", err)
	}

	// Повторная выгрузка в тот же (теперь непустой) dest — ошибка.
	_, err = runTemplateCmd(t, "pull", "a/alpha", "--dest", dest)
	if err == nil {
		t.Fatal("повторный pull в непустой dest должен вернуть ошибку")
	}
	if !strings.Contains(err.Error(), "не пуст") {
		t.Errorf("ошибка не упоминает непустой каталог: %v", err)
	}
}

func TestTemplatePull_DefaultDest(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)

	if err := mgr.Add(ctx, repo.AddOptions{Alias: "a", URL: templateFileURL(newAlphaOrigin(t))}); err != nil {
		t.Fatalf("Add a: %v", err)
	}

	t.Chdir(t.TempDir())
	out, err := runTemplateCmd(t, "pull", "a/alpha")
	if err != nil {
		t.Fatalf("template pull (без --dest): %v\n%s", err, out)
	}
	if _, err := os.Stat("alpha"); err != nil {
		t.Errorf("выгрузка по умолчанию ./alpha не создана: %v", err)
	}
}
