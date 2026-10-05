package contribute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// --- git infrastructure (real git, file:// repository; as in internal/stats) ---

var gitExec = execx.Exec{}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := gitExec.LookPath("git"); err != nil {
		t.Skip("git not found in PATH — integration test skipped")
	}
}

func gitEnv() []string {
	return []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
}

func runGitT(t *testing.T, dir string, args ...string) {
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

// svcManifest — svc template: kafka-toggle (default true), with a files rule for
// a conditional vertical (kafka.go renders when kafka=true).
const svcManifest = `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: "1.0.0"
engine:
  root: files
settings:
  - group: kafka
    title: Kafka
    type: toggle
    default: true
files:
  - when: kafka=true
    paths:
      - "kafka.go"
`

// templateFiles — template tree: main.go.tmpl (slug+module), kafka.go.tmpl
// (conditional vertical), and go.mod.tmpl (to verify go.mod exclusion).
func templateFiles() map[string]string {
	return map[string]string{
		"template.manifest.yaml": svcManifest,
		"files/main.go.tmpl":     "package main\n\n// module {{ .Project.Module }}\nconst slug = \"{{ .Project.Slug }}\"\n",
		"files/kafka.go.tmpl":    "package app\n\n// kafka consumer for {{ .Project.Slug }}\n",
		"files/go.mod.tmpl":      "module {{ .Project.Module }}\n\ngo 1.26\n",
	}
}

func initOrigin(t *testing.T) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	runGitT(t, origin, "init", "-b", "main")
	runGitT(t, origin, "config", "uploadpack.allowFilter", "true")
	// Allow pushing untracked branches to a non-bare origin (we push only the
	// feature branch, but set this explicitly for stability across git versions).
	runGitT(t, origin, "config", "receive.denyCurrentBranch", "refuse")
	for rel, content := range templateFiles() {
		writeFile(t, filepath.Join(origin, rel), content)
	}
	runGitT(t, origin, "add", "-A")
	runGitT(t, origin, "commit", "-m", "init")
	runGitT(t, origin, "tag", "v1.0.0")
	return origin
}

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

// setupProject creates home + the example/svc repository and a demo_svc project
// at v1.0.0. Returns the manager, home, and project directory; the clone gets a
// git identity (in production this comes from the user's git config; contribute does not override it).
func setupProject(t *testing.T) (mgr *repo.Manager, home, projDir string) {
	t.Helper()
	requireGit(t)
	home = filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initOrigin(t)
	mgr = newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("repo add: %v", err)
	}
	// Committer identity in the cached clone (otherwise git commit fails without user.*).
	clone := mgr.CloneDir("example")
	runGitT(t, clone, "config", "user.name", "t")
	runGitT(t, clone, "config", "user.email", "t@e")

	projDir = filepath.Join(t.TempDir(), "proj")
	resolved, err := mgr.ResolveRef("example/svc@v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	src, cleanup, err := mgr.Checkout(context.Background(), resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	raw, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := settings.Resolve(tpl, settings.Values{})
	if err != nil {
		t.Fatal(err)
	}
	project := manifest.ProjectInfo{Name: "demo_svc", Slug: "demo_svc", Module: "example.test/demo_svc"}
	_, err = engine.Render(engine.Options{Source: src, Target: projDir, Template: tpl, Resolved: res, Project: project, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: resolved.RepoAlias})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.SaveSnapshot(filepath.Join(projDir, manifest.SnapshotRelPath), tpl); err != nil {
		t.Fatal(err)
	}
	marker := manifest.Project{APIVersion: manifest.APIVersion, Kind: manifest.KindProject, ID: "fixture-demo_svc", Template: manifest.ProjectTemplate{Repo: resolved.RepoAlias, Name: tpl.Metadata.Name, Version: resolved.Version}, Project: project, Settings: res.Values, Runtime: manifest.ProjectRuntime{Port: 8080}, Baseline: engine.BaselineRelPath}
	markerBytes, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projDir, ".tplaiter", "project.yaml"), markerBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	baselineBytes, err := os.ReadFile(filepath.Join(projDir, filepath.FromSlash(engine.BaselineRelPath)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(baselineBytes)
	projects := state.DefaultProjects()
	projects.Upsert(state.ProjectRef{ID: marker.ID, Path: projDir, Template: state.TemplateSelection{Repo: resolved.RepoAlias, Name: tpl.Metadata.Name, Version: resolved.Version}, CreatedAt: time.Unix(1_700_000_000, 0).UTC(), LastSeenAt: time.Unix(1_700_000_000, 0).UTC(), BaselineSHA: hex.EncodeToString(digest[:])})
	if err := state.SaveProjects(home, projects); err != nil {
		t.Fatal(err)
	}
	return mgr, home, projDir
}

// setRepoType rewrites the repository type in the registry (file:// is detected
// as git; for MR-flow testing we replace it with gitlab — this is test setup, not
// contribute behavior).
func setRepoType(t *testing.T, home string, kind state.RepoKind) {
	t.Helper()
	cfg, err := state.LoadConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Repos {
		cfg.Repos[i].Type = kind
	}
	if err := state.SaveConfig(home, cfg); err != nil {
		t.Fatal(err)
	}
}

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 7, 11, 16, 47, 0, 0, time.UTC) }
}

func testDeps(mgr *repo.Manager, home string, runner execx.Runner, out *bytes.Buffer) Deps {
	return Deps{
		Manager: mgr,
		Runner:  runner,
		Home:    home,
		Out:     out,
		Err:     &bytes.Buffer{},
		Palette: ui.NewPalette(false),
		Picker:  ScriptedPicker{},
		Now:     fixedNow(),
	}
}

// gitShow returns the contents of a path on the origin branch.
func gitShow(t *testing.T, origin, ref, path string) (string, bool) {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git",
		[]string{"show", ref + ":" + path}, execx.Options{Dir: origin, Env: gitEnv()})
	if err != nil {
		return "", false
	}
	return res.Stdout, true
}

func originDir(t *testing.T, home string) string {
	t.Helper()
	cfg, err := state.LoadConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(cfg.Repos[0].URL, "file://")
}

// --- e2e: push + MR ---

func TestUpgrade_E2E_MR(t *testing.T) {
	mgr, home, projDir := setupProject(t)
	setRepoType(t, home, state.RepoKindGitLab)

	// File edit: add a line with the project slug.
	appendToFile(t, filepath.Join(projDir, "main.go"), "\nfunc extra() { _ = \"demo_svc\" }\n")

	rec := execx.NewRecordingRunner()
	rec.OnCommand("glab", execx.Response{Result: execx.Result{Stdout: "https://example.test/example/svc/-/merge_requests/1\n"}})

	var out bytes.Buffer
	res, err := Upgrade(context.Background(), testDeps(mgr, home, rec, &out), Options{
		StartDir: projDir, Yes: true, Title: "contribution",
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if res.Mode != modeMR {
		t.Fatalf("Mode = %q, expected mr", res.Mode)
	}
	wantBranch := "tplater/upgrade-demo_svc-20260711-1647"
	if res.Branch != wantBranch {
		t.Errorf("Branch = %q, expected %q", res.Branch, wantBranch)
	}

	// The .tmpl source path is correct.
	if !contains(res.Files, "files/main.go.tmpl") {
		t.Errorf("Files = %v, expected files/main.go.tmpl", res.Files)
	}

	// The branch was pushed to origin and the file was parameterized again.
	origin := originDir(t, home)
	content, ok := gitShow(t, origin, wantBranch, "files/main.go.tmpl")
	if !ok {
		t.Fatalf("branch %s not found in origin", wantBranch)
	}
	if !strings.Contains(content, "{{ .Project.Slug }}") {
		t.Errorf("main.go.tmpl is not parameterized by slug:\n%s", content)
	}
	if !strings.Contains(content, "{{ .Project.Module }}") {
		t.Errorf("main.go.tmpl is not parameterized by module:\n%s", content)
	}
	if strings.Contains(content, "demo_svc") {
		t.Errorf("literal project values remain in the template:\n%s", content)
	}

	// The MR command was called with the expected arguments.
	glab := findCall(t, rec, "glab")
	assertArgs(t, glab.Args, "mr", "create", "--source-branch", wantBranch, "--title", "contribution")
	if !hasArg(glab.Args, "--description") {
		t.Errorf("no --description in the MR CLI call: %v", glab.Args)
	}
	// The description contains the metadata block.
	desc := argValue(glab.Args, "--description")
	if !strings.Contains(desc, "## tplaiter upgrade") || !strings.Contains(desc, "example/svc@v1.0.0") {
		t.Errorf("description has no metadata block:\n%s", desc)
	}

	// The cached clone returned to the original ref and the branch was deleted locally.
	assertCloneRestored(t, mgr.CloneDir("example"), wantBranch)
}

// --- e2e: --patch ---

func TestUpgrade_E2E_Patch(t *testing.T) {
	mgr, home, projDir := setupProject(t)

	appendToFile(t, filepath.Join(projDir, "main.go"), "\n// tweak by demo_svc\n")

	rec := execx.NewRecordingRunner()
	var out bytes.Buffer
	res, err := Upgrade(context.Background(), testDeps(mgr, home, rec, &out), Options{
		StartDir: projDir, Yes: true, Patch: true,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if res.Mode != modePatch {
		t.Fatalf("Mode = %q, expected patch", res.Mode)
	}
	entries, err := os.ReadDir(res.PatchDir)
	if err != nil {
		t.Fatalf("patch directory: %v", err)
	}
	var patches int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".patch") {
			patches++
		}
	}
	if patches == 0 {
		t.Errorf("no .patch files in %s", res.PatchDir)
	}

	// The MR CLI was not called.
	for _, c := range rec.Calls {
		if c.Name == "glab" || c.Name == "gh" {
			t.Errorf("--patch mode must not call the MR CLI, got: %s %v", c.Name, c.Args)
		}
	}
	assertCloneRestored(t, mgr.CloneDir("example"), res.Branch)
}

// --- conditional vertical → TPLATER-REVIEW marker ---

func TestUpgrade_ConditionalVerticalMarker(t *testing.T) {
	mgr, home, projDir := setupProject(t)

	appendToFile(t, filepath.Join(projDir, "kafka.go"), "\n// user tweak in demo_svc\n")

	rec := execx.NewRecordingRunner()
	var out bytes.Buffer
	res, err := Upgrade(context.Background(), testDeps(mgr, home, rec, &out), Options{
		StartDir: projDir, Yes: true, Patch: true,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	patch := readPatches(t, res.PatchDir)
	if !strings.Contains(patch, "TPLATER-REVIEW") {
		t.Errorf("no TPLATER-REVIEW marker in the kafka.go.tmpl patch:\n%s", patch)
	}
	if !strings.Contains(patch, "conditional vertical kafka=true") {
		t.Errorf("marker lacks the vertical condition:\n%s", patch)
	}
	if !contains(res.Files, "files/kafka.go.tmpl") {
		t.Errorf("Files = %v, expected files/kafka.go.tmpl", res.Files)
	}
}

// --- go.mod excluded; --files adds an extra file ---

func TestUpgrade_GoModExcluded_FilesAddsExtra(t *testing.T) {
	mgr, home, projDir := setupProject(t)

	// Modify go.mod (it must be excluded from candidates).
	appendToFile(t, filepath.Join(projDir, "go.mod"), "\nrequire example.com/x v1.0.0\n")
	// Extra file absent from the reference.
	writeFile(t, filepath.Join(projDir, "docs", "notes.txt"), "operational notes\n")

	rec := execx.NewRecordingRunner()
	var out bytes.Buffer
	res, err := Upgrade(context.Background(), testDeps(mgr, home, rec, &out), Options{
		StartDir: projDir, Patch: true, Files: []string{"docs/*.txt"},
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if contains(res.Files, "files/go.mod.tmpl") || contains(res.Files, "files/go.mod") {
		t.Errorf("go.mod must not be a candidate: %v", res.Files)
	}
	if !contains(res.Files, "files/docs/notes.txt") {
		t.Errorf("extra file from --files was not added: %v", res.Files)
	}
}

// --- substitution deduplication: slug==name==snake does not double-replace ---

func TestBuildSubstitutions_Dedup(t *testing.T) {
	p := manifest.ProjectInfo{
		Name:   "demo_svc",
		Slug:   "demo_svc",
		Module: "example.test/demo_svc",
	}
	subs := buildSubstitutions(p)

	// For value "demo_svc", exactly one substitution should remain — for Slug.
	var slugCount int
	for _, s := range subs {
		if s.value == "demo_svc" {
			slugCount++
			if s.placeholder != "{{ .Project.Slug }}" {
				t.Errorf("value demo_svc was assigned to placeholder %q, expected Slug", s.placeholder)
			}
		}
	}
	if slugCount != 1 {
		t.Errorf("substitutions for demo_svc = %d, expected 1 (dedup slug==name==snake)", slugCount)
	}

	// Module is applied before Slug (otherwise it would split the Go path).
	content := []byte("import \"example.test/demo_svc/pkg\"\nconst s = \"demo_svc\"\n")
	got, changed := derender(content, subs)
	if !changed {
		t.Fatal("derender made no substitutions")
	}
	want := "import \"{{ .Project.Module }}/pkg\"\nconst s = \"{{ .Project.Slug }}\"\n"
	if string(got) != want {
		t.Errorf("derender =\n%q\nexpected\n%q", got, want)
	}
}

// --- helpers ---

func appendToFile(t *testing.T, path, extra string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(data, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readPatches(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("patch directory: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func assertCloneRestored(t *testing.T, clone, branch string) {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git",
		[]string{"symbolic-ref", "--short", "-q", "HEAD"}, execx.Options{Dir: clone})
	if err != nil {
		t.Fatalf("clone HEAD: %v", err)
	}
	if b := strings.TrimSpace(res.Stdout); b != "main" {
		t.Errorf("clone is on branch %q, expected main", b)
	}
	res, _ = gitExec.Run(context.Background(), "git",
		[]string{"branch", "--list", branch}, execx.Options{Dir: clone})
	if strings.TrimSpace(res.Stdout) != "" {
		t.Errorf("branch %s was not deleted locally: %q", branch, res.Stdout)
	}
}

func findCall(t *testing.T, rec *execx.RecordingRunner, name string) execx.Call {
	t.Helper()
	for _, c := range rec.Calls {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no call %q among %v", name, rec.Calls)
	return execx.Call{}
}

func assertArgs(t *testing.T, args []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !hasArg(args, w) {
			t.Errorf("no argument %q in %v", w, args)
		}
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func argValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
