package stats_test

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

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
	"gopkg.in/yaml.v3"
)

// --- git infrastructure (real git, file:// repository; as in internal/update) ---

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

// svcManifest is the svc template manifest with copyWithoutRender and an anchored generator.
func svcManifest(version string) string {
	return `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: svc
  version: ` + version + `
engine:
  root: files
  copyWithoutRender:
    - "**/dashboards/*.json"
requires:
  tplater: ">=0.1.0"
generators:
  - kind: handler
    snippet: gen/handler.txt.tmpl
    target: "handlers/{{ .Name }}.txt"
    anchors:
      - file: wiring.txt
        anchor: "// CODEGEN:WIRING"
        insert: gen/wiring.insert.tmpl
`
}

// versionFiles builds a tag tree: churned.txt changes by version, stable.txt is
// constant, wiring.txt carries a CODEGEN anchor, and dashboards is copyWithoutRender.
func versionFiles(version, churned string) map[string]string {
	return map[string]string{
		"template.manifest.yaml":    svcManifest(version),
		"files/stable.txt":          "constant line\n",
		"files/churned.txt":         churned,
		"files/wiring.txt":          "package app\n// CODEGEN:WIRING\n",
		"files/dashboards/app.json": "{\"slug\":\"__slug__\"}\n",
		"gen/handler.txt.tmpl":      "handler {{ .Name }}\n",
		"gen/wiring.insert.tmpl":    "wire {{ .Name }}\n",
	}
}

// initOrigin creates an origin with sequential tags; each version-to-churned-content
// map entry produces one commit and tag.
func initOrigin(t *testing.T, tags []struct{ version, churned string }) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin")
	if err := os.MkdirAll(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, origin, "init", "-b", "main")
	runGit(t, origin, "config", "uploadpack.allowFilter", "true")
	for _, tag := range tags {
		writeTree(t, origin, versionFiles(tag.version, tag.churned))
		runGit(t, origin, "add", "-A")
		runGit(t, origin, "commit", "-m", tag.version)
		runGit(t, origin, "tag", "v"+tag.version)
	}
	return origin
}

// setupProject creates home and example/svc with the given tags and a fixture
// project at the highest tag (topVersion).
func setupProject(t *testing.T, tags []struct{ version, churned string }, topVersion string) (mgr *repo.Manager, home, projDir string) {
	t.Helper()
	requireGit(t)
	home = filepath.Join(t.TempDir(), "home")
	t.Setenv(state.HomeEnv, home)
	if _, _, err := state.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	origin := initOrigin(t, tags)
	mgr = newManager(t, home)
	if err := mgr.Add(context.Background(), repo.AddOptions{Alias: "example", URL: "file://" + origin}); err != nil {
		t.Fatalf("repo add: %v", err)
	}

	projDir = filepath.Join(t.TempDir(), "proj")
	resolvedRef, err := mgr.ResolveRef("example/svc@v" + topVersion)
	if err != nil {
		t.Fatal(err)
	}
	src, cleanup, err := mgr.Checkout(context.Background(), resolvedRef.RepoAlias, resolvedRef.GitRef, resolvedRef.Entry.Path)
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
	resolved, err := settings.Resolve(tpl, settings.Values{})
	if err != nil {
		t.Fatal(err)
	}
	projectInfo := manifest.ProjectInfo{Name: "demo_svc", Slug: "demo_svc", Module: "example.test/demo_svc"}
	_, err = engine.Render(engine.Options{Source: src, Target: projDir, Template: tpl, Resolved: resolved, Project: projectInfo, Runtime: manifest.ProjectRuntime{Port: 8080}, Repo: resolvedRef.RepoAlias})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.SaveSnapshot(filepath.Join(projDir, manifest.SnapshotRelPath), tpl); err != nil {
		t.Fatal(err)
	}
	marker := manifest.Project{APIVersion: manifest.APIVersion, Kind: manifest.KindProject, ID: "fixture-demo_svc", Template: manifest.ProjectTemplate{Repo: resolvedRef.RepoAlias, Name: tpl.Metadata.Name, Version: resolvedRef.Version}, Project: projectInfo, Settings: resolved.Values, Runtime: manifest.ProjectRuntime{Port: 8080}, Baseline: engine.BaselineRelPath}
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
	now := time.Unix(1_700_000_000, 0).UTC()
	projects := state.DefaultProjects()
	projects.Upsert(state.ProjectRef{ID: marker.ID, Path: projDir, Template: state.TemplateSelection{Repo: resolvedRef.RepoAlias, Name: tpl.Metadata.Name, Version: resolvedRef.Version}, CreatedAt: now, LastSeenAt: now, BaselineSHA: hex.EncodeToString(digest[:])})
	if err := state.SaveProjects(home, projects); err != nil {
		t.Fatal(err)
	}
	return mgr, home, projDir
}

func testDeps(mgr *repo.Manager, home string, out, errOut *bytes.Buffer) stats.Deps {
	return stats.Deps{
		Manager: mgr,
		Home:    home,
		Out:     out,
		Err:     errOut,
		Palette: ui.NewPalette(false),
	}
}

// threeTagSet has three tags; churned.txt changes v1 to v2 and is stable v2->v3.
func threeTagSet() []struct{ version, churned string } {
	return []struct{ version, churned string }{
		{"0.1.0", "old churn\n"},
		{"0.2.0", "new churn\n"},
		{"0.3.0", "new churn\n"},
	}
}

// Zero drift immediately after new -> score 0, "project matches the template".
func TestStats_E2E_ZeroDrift(t *testing.T) {
	mgr, home, projDir := setupProject(t, threeTagSet(), "0.3.0")

	rep, err := stats.Collect(context.Background(), testDeps(mgr, home, &bytes.Buffer{}, &bytes.Buffer{}), projDir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if rep.Score != 0 {
		t.Errorf("score = %d, ожидался 0 сразу после new", rep.Score)
	}
	if len(rep.Extras) != 0 {
		t.Errorf("extras = %v, ожидались пустые", rep.Extras)
	}

	var out, errOut bytes.Buffer
	if err := stats.Run(context.Background(), testDeps(mgr, home, &out, &errOut), stats.Options{StartDir: projDir}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "проект соответствует шаблону") {
		t.Errorf("нет сообщения о соответствии:\n%s", out.String())
	}
}

// conflict-prone: a file changed between tags is edited in work -> conflict-prone;
// a stable file -> auto.
func TestStats_E2E_ConflictProneVsAuto(t *testing.T) {
	mgr, home, projDir := setupProject(t, threeTagSet(), "0.3.0")

	// Edit both files in the work tree.
	writeTree(t, projDir, map[string]string{
		"churned.txt": "USER churn\n",
		"stable.txt":  "USER stable\n",
	})

	rep, err := stats.Collect(context.Background(), testDeps(mgr, home, &bytes.Buffer{}, &bytes.Buffer{}), projDir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	classOf := func(path string) string {
		for _, f := range rep.Files {
			if f.Path == path {
				return f.Class
			}
		}
		t.Fatalf("нет файла %q в отчёте", path)
		return ""
	}
	if c := classOf("churned.txt"); c != stats.ClassConflictProne {
		t.Errorf("churned.txt класс = %q, ожидался conflict-prone", c)
	}
	if c := classOf("stable.txt"); c != stats.ClassAuto {
		t.Errorf("stable.txt класс = %q, ожидался auto", c)
	}
	if len(rep.Warnings) != 0 {
		t.Errorf("не ожидались предупреждения при 3 тегах: %v", rep.Warnings)
	}
}

// Broken anchor through the full pipeline: remove the CODEGEN line -> manual-only.
func TestStats_E2E_BrokenAnchor(t *testing.T) {
	mgr, home, projDir := setupProject(t, threeTagSet(), "0.3.0")

	writeTree(t, projDir, map[string]string{"wiring.txt": "package app\n"}) // anchor removed

	rep, err := stats.Collect(context.Background(), testDeps(mgr, home, &bytes.Buffer{}, &bytes.Buffer{}), projDir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rep.BrokenAnchors) != 1 || rep.BrokenAnchors[0] != "wiring.txt" {
		t.Errorf("brokenAnchors = %v, ожидался [wiring.txt]", rep.BrokenAnchors)
	}
	for _, f := range rep.Files {
		if f.Path == "wiring.txt" && f.Class != stats.ClassManualOnly {
			t.Errorf("wiring.txt класс = %q, ожидался manual-only", f.Class)
		}
	}
}

// copyWithoutRender artifact: dashboard edit -> manual-only through the pipeline.
func TestStats_E2E_CopyWithoutRender(t *testing.T) {
	mgr, home, projDir := setupProject(t, threeTagSet(), "0.3.0")

	writeTree(t, projDir, map[string]string{"dashboards/app.json": "{\"slug\":\"demo_svc\",\"x\":1}\n"})

	rep, err := stats.Collect(context.Background(), testDeps(mgr, home, &bytes.Buffer{}, &bytes.Buffer{}), projDir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, f := range rep.Files {
		if f.Path == "dashboards/app.json" && f.Class != stats.ClassManualOnly {
			t.Errorf("dashboards/app.json класс = %q, ожидался manual-only", f.Class)
		}
	}
}

// <2 tags -> warning that the historical heuristic is unavailable; edits are auto.
func TestStats_E2E_HistoryUnavailable(t *testing.T) {
	oneTag := []struct{ version, churned string }{{"0.1.0", "only\n"}}
	mgr, home, projDir := setupProject(t, oneTag, "0.1.0")

	writeTree(t, projDir, map[string]string{"churned.txt": "USER\n"})

	var out, errOut bytes.Buffer
	rep, err := stats.Collect(context.Background(), testDeps(mgr, home, &out, &errOut), projDir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "недоступна") {
		t.Errorf("ожидалось предупреждение о недоступности эвристики, получено: %v", rep.Warnings)
	}
	for _, f := range rep.Files {
		if f.Path == "churned.txt" && f.Class != stats.ClassAuto {
			t.Errorf("при <2 тегах правка должна быть auto, стало %q", f.Class)
		}
	}

	// Run prints a warning to Err.
	if err := stats.Run(context.Background(), testDeps(mgr, home, &out, &errOut), stats.Options{StartDir: projDir}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(errOut.String(), "недоступна") {
		t.Errorf("Run не напечатал предупреждение в Err:\n%s", errOut.String())
	}
}
