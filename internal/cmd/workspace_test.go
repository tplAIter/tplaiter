package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
)

// Фикстуры для `tplater workspace add-service`: репозиторий example с ОДНИМ
// шаблоном svc (labels.type=service) — resolveServiceTemplateName находит его
// по репозиторию текущего workspace-проекта. Сам workspace-корень нарочно НЕ
// зарегистрирован как шаблон в репозитории: LoadManifestForProject падает на
// repoSource (ResolveRef "example/wsroot@1.0.0" не находит такого шаблона) и уходит
// в SnapshotSource — это штатный, разрешённый путь (см. internal/project/source.go),
// и он сильно упрощает фикстуру (не нужен полноценный workspace-шаблон/рендер
// для самого корня, только go.work + маркер + снимок).

const workspaceSvcRepoManifest = `apiVersion: tplater.dev/v1alpha1
kind: Repository
metadata:
  name: ws-templates
templates:
  - path: svc/
`

const workspaceSvcManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: "1.0.0"
  description: "Service template fixture"
  labels:
    type: [service]
engine:
  type: gotemplate
  root: files
settings:
  - group: workflow
    title: "Temporal workflow"
    type: toggle
    default: false
`

const workspaceSvcMainGo = "package main\n\nfunc main() {}\n"

// workspaceSvcManifestNoWorkflow — тот же фикстурный сервис-шаблон, но БЕЗ
// settings-группы workflow: воспроизводит находку про форсированный
// --set workflow=true, падающий на шаблоне без такой группы.
const workspaceSvcManifestNoWorkflow = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: "1.0.0"
  description: "Service template fixture without workflow group"
  labels:
    type: [service]
engine:
  type: gotemplate
  root: files
`

func newWorkspaceSvcOriginNoWorkflow(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "repo.manifest.yaml"), workspaceSvcRepoManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "template.manifest.yaml"), workspaceSvcManifestNoWorkflow)
	writeTestFile(t, filepath.Join(origin, "svc", "files", "main.go.tmpl"), workspaceSvcMainGo)
	commitAllForTemplateTests(t, origin)
	return origin
}

// workspaceSvcManifestWorkflowWrongType — фикстурный сервис-шаблон с группой
// workflow, но НЕ toggle (select вместо ожидаемого toggle): воспроизводит
// ветку serviceTemplateHasGroup, где группа объявлена, но форсируемое
// значение "true" ей не подходит — это уже не «группы нет» (best-effort), а
// реальный конфликт манифеста, который должен остаться жёсткой ошибкой.
const workspaceSvcManifestWorkflowWrongType = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: "1.0.0"
  description: "Service template fixture with workflow group of incompatible type"
  labels:
    type: [service]
engine:
  type: gotemplate
  root: files
settings:
  - group: workflow
    title: "Workflow mode"
    type: select
    default: sync
    options:
      - id: sync
      - id: async
`

func newWorkspaceSvcOriginWorkflowWrongType(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "repo.manifest.yaml"), workspaceSvcRepoManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "template.manifest.yaml"), workspaceSvcManifestWorkflowWrongType)
	writeTestFile(t, filepath.Join(origin, "svc", "files", "main.go.tmpl"), workspaceSvcMainGo)
	commitAllForTemplateTests(t, origin)
	return origin
}

// newWorkspaceSvcOrigin строит origin-репозиторий с одним шаблоном svc
// (type=service) — сервис-action, который `workspace add-service` разворачивает
// в services/<slug>.
func newWorkspaceSvcOrigin(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "repo.manifest.yaml"), workspaceSvcRepoManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "template.manifest.yaml"), workspaceSvcManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "files", "main.go.tmpl"), workspaceSvcMainGo)
	commitAllForTemplateTests(t, origin)
	return origin
}

// workspaceRootSnapshot — снимок манифеста workspace-корня (labels.type=workspace),
// на который LoadManifestForProject падает через SnapshotSource.
const workspaceRootSnapshot = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: wsroot
  version: "1.0.0"
  description: "Workspace root fixture"
  labels:
    type: [workspace]
`

// workspaceRootProject — маркер .tplaiter/project.yaml workspace-корня. repo=example
// совпадает с алиасом репозитория сервис-шаблона — resolveServiceTemplateName
// ищет type=service именно в proj.Template.Repo.
const workspaceRootProject = `apiVersion: tplater.dev/v1alpha1
kind: Project
id: ws-test-id
template:
  repo: example
  name: wsroot
  version: "1.0.0"
project:
  name: WS Root
  slug: ws_root
  module: example.com/ws_root
`

// nonWorkspaceRootSnapshot/-Project — проект того же вида, но БЕЗ
// labels.type=workspace: `workspace add-service` должен отказать.
const nonWorkspaceRootSnapshot = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: plainroot
  version: "1.0.0"
  description: "Не workspace"
  labels:
    type: [service]
`

const nonWorkspaceRootProject = `apiVersion: tplater.dev/v1alpha1
kind: Project
id: plain-test-id
template:
  repo: example
  name: plainroot
  version: "1.0.0"
project:
  name: Plain Root
  slug: plain_root
  module: example.com/plain_root
`

// newWorkspaceHome готовит изолированный TPLAITER_HOME с репозиторием example
// (шаблон сервиса svc); дальнейшие вызовы команды `workspace` через
// runWorkspaceCmd открывают собственный repo.Manager поверх того же
// TPLAITER_HOME (см. newManager в internal/cmd/repo.go), поэтому возвращать
// менеджер отсюда вызывающим не нужно.
func newWorkspaceHome(t *testing.T) {
	t.Helper()
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "example", URL: templateFileURL(newWorkspaceSvcOrigin(t))}); err != nil {
		t.Fatalf("Add example: %v", err)
	}
}

// newWorkspaceHomeNoWorkflow — вариант newWorkspaceHome с сервис-шаблоном,
// в манифесте которого нет settings-группы workflow (см.
// TestWorkspaceAddService_ServiceTemplateMissingWorkflowGroup_BestEffort).
func newWorkspaceHomeNoWorkflow(t *testing.T) {
	t.Helper()
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "example", URL: templateFileURL(newWorkspaceSvcOriginNoWorkflow(t))}); err != nil {
		t.Fatalf("Add example: %v", err)
	}
}

// newWorkspaceHomeWorkflowWrongType — вариант newWorkspaceHome с
// сервис-шаблоном, где группа workflow есть, но не toggle (см.
// TestWorkspaceAddService_ServiceTemplateWorkflowGroupWrongType).
func newWorkspaceHomeWorkflowWrongType(t *testing.T) {
	t.Helper()
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "example", URL: templateFileURL(newWorkspaceSvcOriginWorkflowWrongType(t))}); err != nil {
		t.Fatalf("Add example: %v", err)
	}
}

// chdirTemp меняет текущий рабочий каталог процесса на dir на время теста,
// восстанавливая прежний через t.Cleanup (по образцу newRunFixture в run_test.go).
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })
}

// runWorkspaceCmd исполняет свежесобранное дерево команд `workspace` (по
// образцу runTemplateCmd/runRunCmd в соседних тестах этого пакета).
func runWorkspaceCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := newWorkspaceCmd()
	out := &strings.Builder{}
	c.SetOut(out)
	c.SetErr(out)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func TestWorkspaceAddService_HappyPath(t *testing.T) {
	newWorkspaceHome(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), workspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), workspaceRootSnapshot)
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\n")
	chdirTemp(t, root)

	assertWorkspaceAddServiceUnavailable(t, root, "Billing")
}

func TestWorkspaceAddService_OutsideProject(t *testing.T) {
	newWorkspaceHome(t)
	chdirTemp(t, t.TempDir())

	_, err := runWorkspaceCmd(t, "add-service", "billing", "--defaults")
	if err == nil {
		t.Fatal("workspace add-service вне проекта: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "не является проектом tplater") {
		t.Errorf("ошибка не упоминает отсутствие проекта: %v", err)
	}
}

func TestWorkspaceAddService_NotWorkspaceKind(t *testing.T) {
	newWorkspaceHome(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), nonWorkspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), nonWorkspaceRootSnapshot)
	chdirTemp(t, root)

	_, err := runWorkspaceCmd(t, "add-service", "billing", "--defaults")
	if err == nil {
		t.Fatal("workspace add-service в не-workspace проекте: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "не является workspace") {
		t.Errorf("ошибка не упоминает несовпадение kind=workspace: %v", err)
	}
}

// TestWorkspaceAddService_ExistingServiceDir проверяет ветку, где
// services/<slug> уже существует (например, остаток от прежней попытки) —
// newcmd.ensureVacant должен отказать ДО каких-либо изменений (go.work не
// трогается).
func TestWorkspaceAddService_ExistingServiceDir(t *testing.T) {
	newWorkspaceHome(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), workspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), workspaceRootSnapshot)
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\n")
	writeTestFile(t, filepath.Join(root, "services", "billing", "leftover.txt"), "stale\n")
	chdirTemp(t, root)

	_, err := runWorkspaceCmd(t, "add-service", "Billing", "--defaults", "--no-hooks", "--no-deps-check", "--no-env-setup")
	if err == nil {
		t.Fatal("workspace add-service с уже существующим services/<slug>: ожидалась ошибка")
	}

	work, rerr := os.ReadFile(filepath.Join(root, "go.work"))
	if rerr != nil {
		t.Fatalf("чтение go.work: %v", rerr)
	}
	if strings.Contains(string(work), "services/billing") {
		t.Errorf("go.work не должен был измениться при провале до рендера: %s", work)
	}
}

// TestWorkspaceAddService_FromNestedServiceDir воспроизводит находку: запуск
// из services/<slug> (у него свой .tplaiter/project.yaml, созданный самой
// командой) не должен падать «не является workspace» — findWorkspaceRoot
// обязан подняться к настоящему workspace-корню.
func TestWorkspaceAddService_FromNestedServiceDir(t *testing.T) {
	newWorkspaceHome(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), workspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), workspaceRootSnapshot)
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\n")
	chdirTemp(t, root)

	// Keep the pure workspace-root discovery case covered without creating a
	// service: a nested project marker must not hide the workspace root.
	svcDir := filepath.Join(root, "services", "billing")
	writeTestFile(t, filepath.Join(svcDir, ".tplaiter", "project.yaml"), nonWorkspaceRootProject)
	writeTestFile(t, filepath.Join(svcDir, ".tplaiter", "manifest.snapshot.yaml"), nonWorkspaceRootSnapshot)
	home, _, err := state.EnsureHome()
	if err != nil {
		t.Fatal(err)
	}
	located, _, _, err := findWorkspaceRoot(home, svcDir)
	if err != nil || located != root {
		t.Fatalf("findWorkspaceRoot nested = %q, %v; want %q", located, err, root)
	}
	chdirTemp(t, svcDir)
	assertWorkspaceAddServiceUnavailable(t, root, "Payments")
}

// TestWorkspaceAddService_ServiceTemplateMissingWorkflowGroup_BestEffort
// воспроизводит находку ревью: форсированный --set workflow=true раньше падал
// на шаблоне сервиса без такой группы сырой ошибкой ParseSet («неизвестная
// группа "workflow"»). Теперь это best-effort (serviceTemplateHasGroup в
// workspace.go проверяет манифест ДО установки) — команда предупреждает и
// продолжает без forced-значения, сервис отрисовывается и регистрируется в
// go.work как обычно.
func TestWorkspaceAddService_ServiceTemplateMissingWorkflowGroup_BestEffort(t *testing.T) {
	newWorkspaceHomeNoWorkflow(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), workspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), workspaceRootSnapshot)
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\n")
	chdirTemp(t, root)

	assertWorkspaceAddServiceUnavailable(t, root, "Billing")
}

func assertWorkspaceAddServiceUnavailable(t *testing.T, root, name string) {
	t.Helper()
	workPath := filepath.Join(root, "go.work")
	before, err := os.ReadFile(workPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runWorkspaceCmd(t, "add-service", name, "--defaults", "--no-hooks", "--no-deps-check", "--no-env-setup")
	if !errors.Is(err, newcmd.ErrLifecycleUnavailable) {
		t.Fatalf("workspace add-service error = %v, want %v", err, newcmd.ErrLifecycleUnavailable)
	}
	after, err := os.ReadFile(workPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("go.work changed on unavailable lifecycle: %q, %v", after, err)
	}
	slug, err := newcmd.Slugify(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "services", slug)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service directory created on unavailable lifecycle: %v", err)
	}
}

// TestWorkspaceAddService_ServiceTemplateWorkflowGroupWrongType — в отличие
// от best-effort-теста выше, здесь группа workflow В МАНИФЕСТЕ ЕСТЬ, но не
// toggle (select) — serviceTemplateHasGroup должен вернуть жёсткую ошибку
// (несовместимый тип — это не «группы нет»), а не молча продолжить без
// форса.
func TestWorkspaceAddService_ServiceTemplateWorkflowGroupWrongType(t *testing.T) {
	newWorkspaceHomeWorkflowWrongType(t)

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".tplaiter", "project.yaml"), workspaceRootProject)
	writeTestFile(t, filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), workspaceRootSnapshot)
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.23\n")
	chdirTemp(t, root)

	_, err := runWorkspaceCmd(t, "add-service", "Billing", "--defaults", "--no-hooks", "--no-deps-check", "--no-env-setup")
	if err == nil {
		t.Fatal("workspace add-service на шаблоне с group workflow типа select: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "workflow") {
		t.Errorf("ошибка не упоминает группу workflow: %v", err)
	}
	if !strings.Contains(err.Error(), "несовместима") {
		t.Errorf("ошибка не поясняет несовместимость типа группы с форсируемым значением: %v", err)
	}

	// go.work не должен был измениться — рендер не дошёл до конца.
	work, rerr := os.ReadFile(filepath.Join(root, "go.work"))
	if rerr != nil {
		t.Fatalf("чтение go.work: %v", rerr)
	}
	if strings.Contains(string(work), "services/billing") {
		t.Errorf("go.work не должен был измениться при провале проверки настроек: %s", work)
	}
}

// fakeTemplateIndex — минимальная реализация интерфейса, который принимает
// resolveServiceTemplateName, без repo.Manager/git-фикстур.
type fakeTemplateIndex map[string][]state.TemplateEntry

func (f fakeTemplateIndex) Templates() (map[string][]state.TemplateEntry, error) {
	return f, nil
}

func TestResolveServiceTemplateName_NoMatches(t *testing.T) {
	idx := fakeTemplateIndex{
		"example": {
			{Name: "lib", LabelsFlat: map[string][]string{"type": {"library"}}},
		},
	}
	_, err := resolveServiceTemplateName(idx, "example")
	if err == nil {
		t.Fatal("0 совпадений type=service: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "не найден шаблон") {
		t.Errorf("ошибка не про отсутствие шаблона: %v", err)
	}
}

func TestResolveServiceTemplateName_MultipleMatches(t *testing.T) {
	idx := fakeTemplateIndex{
		"example": {
			{Name: "svc-a", LabelsFlat: map[string][]string{"type": {"service"}}},
			{Name: "svc-b", LabelsFlat: map[string][]string{"type": {"service"}}},
		},
	}
	_, err := resolveServiceTemplateName(idx, "example")
	if err == nil {
		t.Fatal("2+ совпадений type=service: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "svc-a") || !strings.Contains(err.Error(), "svc-b") {
		t.Errorf("ошибка не перечисляет оба совпадения: %v", err)
	}
}

// TestAddWorkspaceUse_Idempotent — прямой unit-тест идемпотентности (без
// проходов через полный CLI-флоу): второй вызов с уже зарегистрированным
// путём не задваивает use-директиву, в т.ч. когда существующая строка в
// go.work записана без ведущего "./" (валидный ручной синтаксис go.work).
func TestAddWorkspaceUse_Idempotent(t *testing.T) {
	root := t.TempDir()
	workPath := filepath.Join(root, "go.work")
	writeTestFile(t, workPath, "go 1.23\n\nuse services/billing\n")

	if err := addWorkspaceUse(root, "./services/billing"); err != nil {
		t.Fatalf("addWorkspaceUse (уже есть без ./): %v", err)
	}
	data, err := os.ReadFile(workPath)
	if err != nil {
		t.Fatalf("чтение go.work: %v", err)
	}
	if n := strings.Count(string(data), "services/billing"); n != 1 {
		t.Errorf("services/billing встречается %d раз(а), ожидался 1:\n%s", n, data)
	}

	// Повторный вызов с тем же путём — тоже не задваивает.
	if err := addWorkspaceUse(root, "./services/billing"); err != nil {
		t.Fatalf("addWorkspaceUse (повторно): %v", err)
	}
	data, err = os.ReadFile(workPath)
	if err != nil {
		t.Fatalf("чтение go.work: %v", err)
	}
	if n := strings.Count(string(data), "services/billing"); n != 1 {
		t.Errorf("после повторного вызова services/billing встречается %d раз(а), ожидался 1:\n%s", n, data)
	}

	// Новый путь дописывается как обычно.
	if err := addWorkspaceUse(root, "./services/payments"); err != nil {
		t.Fatalf("addWorkspaceUse (новый путь): %v", err)
	}
	data, err = os.ReadFile(workPath)
	if err != nil {
		t.Fatalf("чтение go.work: %v", err)
	}
	if !strings.Contains(string(data), "services/payments") {
		t.Errorf("go.work не содержит новый путь services/payments:\n%s", data)
	}
}
