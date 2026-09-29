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

// gitExec is the real git runner for building test repositories (through
// internal/execx rather than direct os/exec, as required by depguard).
var gitExec = execx.Exec{}

// requireGit skips the test when git is unavailable, for example in minimal CI.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH — integration test skipped")
	}
}

// gitEnv is deterministic git environment for commits without global config
// (execx adds it to os.Environ()).
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

// initOrigin creates a "remote" repository in a new directory with a main
// branch and partial clone enabled (uploadpack.allowFilter) for --filter=blob:none.
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

// newIntegrationManager builds a manager with real git and an isolated home/store.
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

	// List: one repository, one template, kind git (file://).
	infos, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 1 || infos[0].Ref.Alias != "example" || infos[0].Templates != 1 {
		t.Fatalf("List = %+v", infos)
	}
	if infos[0].Ref.Type != state.RepoKindGit {
		t.Errorf("type = %q, want git", infos[0].Ref.Type)
	}

	// Index: two stable tags, highest is v1.1.0.
	res, err := m.ResolveRef("go-service")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if res.Version != "v1.1.0" || res.GitRef != "v1.1.0" {
		t.Errorf("resolve default = %+v, want v1.1.0", res)
	}

	// Checkout at the old tag returns that version's content.
	assertCheckout(ctx, t, m, "example", "v1.0.0", ".", "hello.txt", "v1.0.0\n")

	// Update: add a tag on the remote side; fetch must see it.
	runGit(t, origin, "tag", "v1.2.0")
	if err := m.Update(ctx, "example"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	res, err = m.ResolveRef("go-service")
	if err != nil {
		t.Fatalf("ResolveRef after update: %v", err)
	}
	if res.Version != "v1.2.0" {
		t.Errorf("after update the latest tag = %q, want v1.2.0", res.Version)
	}

	// Remove: config, index, and clone disappear.
	if err := m.Remove("example"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	infos, _ = m.List()
	if len(infos) != 0 {
		t.Errorf("after Remove List = %+v", infos)
	}
	if _, err := os.Stat(m.cloneDir("example")); !os.IsNotExist(err) {
		t.Errorf("clone not removed: %v", err)
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
		t.Fatalf("List = %+v, want 2 templates", infos)
	}

	// alpha has the namespaced tag alpha/v0.1.0.
	res, err := m.ResolveRef("example/alpha")
	if err != nil {
		t.Fatalf("ResolveRef alpha: %v", err)
	}
	if res.GitRef != "alpha/v0.1.0" || res.Version != "v0.1.0" {
		t.Errorf("alpha resolve = %+v", res)
	}
	// beta has no tags, so latest uses the branch.
	resB, err := m.ResolveRef("example/beta")
	if err != nil {
		t.Fatalf("ResolveRef beta: %v", err)
	}
	if resB.Version != "latest" {
		t.Errorf("beta resolve = %+v, want latest", resB)
	}

	// Checking out alpha at its tag returns the expected subdirectory.
	assertCheckout(ctx, t, m, "example", "alpha/v0.1.0", "alpha", "marker.txt", "alpha-v0.1.0\n")
}

func TestIntegration_AutoScanNoRepoManifest(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	// No repo.manifest.yaml at the root: auto-scan */template.manifest.yaml.
	writeFile(t, filepath.Join(origin, "svc-a", templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc-a
  version: "1.0.0"
`)
	// Depth 2: group/svc-b/template.manifest.yaml.
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
		t.Fatalf("auto-scan did not find exactly 2 templates: %+v", infos)
	}
	if _, err := m.ResolveRef("svc-b"); err != nil {
		t.Errorf("ResolveRef svc-b (depth 2): %v", err)
	}
}

func TestIntegration_BrokenManifestFailsAdd(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	// A manifest without required metadata.name/version fields makes Validate fail.
	writeFile(t, filepath.Join(origin, templateManifestName), `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  description: "no name and no version"
`)
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	err := m.Add(ctx, AddOptions{Alias: "bad", URL: fileURL(origin)})
	if err == nil {
		t.Fatal("Add must fail on a broken manifest")
	}
	if !strings.Contains(err.Error(), templateManifestName) {
		t.Errorf("error lacks the manifest path: %v", err)
	}
	// The repository is NOT registered and the clone is removed.
	infos, _ := m.List()
	if len(infos) != 0 {
		t.Errorf("broken repository was registered: %+v", infos)
	}
	if _, statErr := os.Stat(m.cloneDir("bad")); !os.IsNotExist(statErr) {
		t.Errorf("broken repository clone was not removed")
	}
}

// assertCheckout verifies that Checkout(alias, ref, templatePath) returns an
// fs.FS whose wantFile contains wantContent.
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
		t.Fatalf("reading %s: %v", wantFile, err)
	}
	if string(data) != wantContent {
		t.Errorf("%s = %q, want %q", wantFile, string(data), wantContent)
	}
}
