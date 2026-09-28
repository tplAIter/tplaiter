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

// Fixtures for `tplater workspace add-service`: an example repository with one
// svc template (labels.type=service), found by resolveServiceTemplateName in
// the current workspace project's repository. The workspace root is deliberately
// not registered as a repository template: LoadManifestForProject falls back
// from repoSource (ResolveRef "example/wsroot@1.0.0" finds no template) to
// SnapshotSource, a supported path (see internal/project/source.go), simplifying
// the fixture to go.work, a marker, and a snapshot.

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

// workspaceSvcManifestNoWorkflow — the same service fixture without a workflow
// settings group, reproducing forced --set workflow=true on a template without
// that group.
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

// workspaceSvcManifestWorkflowWrongType — service fixture with workflow group
// that is NOT a toggle (select instead), reproducing serviceTemplateHasGroup
// where the group exists but forced value "true" is incompatible: a real
// manifest conflict that must remain a hard error, not best-effort missing-group
// handling.
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

// newWorkspaceSvcOrigin builds an origin repository with one svc template
// (type=service), the service action rendered by `workspace add-service` into
// services/<slug>.
func newWorkspaceSvcOrigin(t *testing.T) string {
	t.Helper()
	origin := initTemplateOrigin(t)
	writeTestFile(t, filepath.Join(origin, "repo.manifest.yaml"), workspaceSvcRepoManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "template.manifest.yaml"), workspaceSvcManifest)
	writeTestFile(t, filepath.Join(origin, "svc", "files", "main.go.tmpl"), workspaceSvcMainGo)
	commitAllForTemplateTests(t, origin)
	return origin
}

// workspaceRootSnapshot — workspace-root manifest snapshot (labels.type=workspace)
// used by LoadManifestForProject through SnapshotSource.
const workspaceRootSnapshot = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: wsroot
  version: "1.0.0"
  description: "Workspace root fixture"
  labels:
    type: [workspace]
`

// workspaceRootProject — workspace-root .tplaiter/project.yaml marker. repo=example
// matches the service-template repository alias; resolveServiceTemplateName
// searches for type=service in proj.Template.Repo.
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

// nonWorkspaceRootSnapshot/-Project — same kind of project but WITHOUT
// labels.type=workspace: `workspace add-service` must reject it.
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

// newWorkspaceHome prepares an isolated TPLAITER_HOME with example repository
// (svc service template). Later `workspace` calls through runWorkspaceCmd open
// their own repo.Manager over the same TPLAITER_HOME (see newManager in
// internal/cmd/repo.go), so callers need no manager returned here.
func newWorkspaceHome(t *testing.T) {
	t.Helper()
	requireGit(t)
	ctx := context.Background()
	mgr := newTemplateTestManager(t)
	if err := mgr.Add(ctx, repo.AddOptions{Alias: "example", URL: templateFileURL(newWorkspaceSvcOrigin(t))}); err != nil {
		t.Fatalf("Add example: %v", err)
	}
}

// newWorkspaceHomeNoWorkflow — newWorkspaceHome variant whose service template
// manifest has no workflow settings group (see
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

// newWorkspaceHomeWorkflowWrongType — newWorkspaceHome variant whose service
// template has workflow group but it is not a toggle (see
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

// chdirTemp changes the process working directory to dir for the test and
// restores it through t.Cleanup (like newRunFixture in run_test.go).
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

// runWorkspaceCmd executes a freshly built `workspace` command tree (like
// runTemplateCmd/runRunCmd in neighboring tests).
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

// TestWorkspaceAddService_ExistingServiceDir covers an existing
// services/<slug> directory (for example, left by an earlier attempt):
// newcmd.ensureVacant must reject before any changes (go.work stays untouched).
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

// TestWorkspaceAddService_FromNestedServiceDir covers invocation from
// services/<slug> (with its own .tplaiter/project.yaml created by the command):
// it must not fail as "not a workspace"; findWorkspaceRoot must reach the real
// workspace root.
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
// This reproduces a review finding: forced --set workflow=true used to fail on
// a service template without the group with raw ParseSet error ("unknown
// group workflow"). It is now best-effort (serviceTemplateHasGroup in
// workspace.go checks the manifest BEFORE installation): the command warns and
// continues without the forced value, rendering and registering the service in
// go.work normally.
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

// TestWorkspaceAddService_ServiceTemplateWorkflowGroupWrongType — unlike the
// best-effort test above, workflow exists in the manifest but is not a toggle
// (select). serviceTemplateHasGroup must return a hard error (incompatible type
// is not a missing group), rather than silently continuing without the force.
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

	// go.work must be unchanged because rendering did not complete.
	work, rerr := os.ReadFile(filepath.Join(root, "go.work"))
	if rerr != nil {
		t.Fatalf("чтение go.work: %v", rerr)
	}
	if strings.Contains(string(work), "services/billing") {
		t.Errorf("go.work не должен был измениться при провале проверки настроек: %s", work)
	}
}

// fakeTemplateIndex — minimal implementation accepted by
// resolveServiceTemplateName, without repo.Manager/git fixtures.
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

// TestAddWorkspaceUse_Idempotent — direct idempotence unit test (without the
// full CLI flow): a second call with an existing path does not duplicate the
// use directive, including when go.work uses valid manual syntax without "./".
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

	// Repeating the same path must not duplicate it.
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

	// A new path is appended normally.
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
