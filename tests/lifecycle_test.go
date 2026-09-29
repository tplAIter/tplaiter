package e2e

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestLifecycle runs the full project lifecycle as a black box
// (scenario 1, implementation requirement): init-template (git init/commit
// enabled by default) -> repo add file:// -> template list/show -> new (--set +
// --defaults) -> run test -> settings set -> update --check -> stats --json
// -> projects list.
//
// The template source is `tplater init-template` (internal/inittemplate), not
// testdata/fixtures: its skeleton carries settings (feature_x toggle, variant
// select), a files rule, commands, a hook, generators, ai-config, and an
// environment playbook — the only repository fixture covering ALL subcommands
// in this scenario in one pass.
func TestLifecycle(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	base := t.TempDir()
	repoDir := filepath.Join(base, "demo-svc-repo")
	projDir := filepath.Join(base, "proj")

	// 1. init-template: generates the template repository + git init/commit.
	mustRun(t, home, "", "init-template", "demo-svc", "--dir", repoDir)
	if !exists(filepath.Join(repoDir, ".git")) {
		t.Fatalf("init-template: expected a git repository in %s", repoDir)
	}
	if !exists(filepath.Join(repoDir, "template.manifest.yaml")) {
		t.Fatalf("init-template: expected template.manifest.yaml in %s", repoDir)
	}

	// 2. repo add file://<repoDir>.
	mustRun(t, home, "", "repo", "add", "example", "file://"+repoDir)

	// 3. template list / list filtered by label / show.
	list := mustRun(t, home, "", "template", "list")
	mustContain(t, list.Stdout, "demo-svc", "template list")

	filtered := mustRun(t, home, "", "template", "list", "-l", "lang=example")
	mustContain(t, filtered.Stdout, "demo-svc", "template list -l lang=example")

	show := mustRun(t, home, "", "template", "show", "example/demo-svc")
	mustContain(t, show.Stdout, "demo-svc", "template show")

	// 4. new: --set overrides feature_x/variant, while --defaults takes the
	// rest (the nested verbose toggle under variant=advanced) from manifest defaults.
	skipAtLiveLifecycle(
		t, home, "new", "example/demo-svc", "My Service",
		"--dir", projDir,
		"--module", "example.com/my-service",
		"--set", "feature_x=true",
		"--set", "variant=advanced",
		"--defaults",
	)

	readme := mustReadFile(t, filepath.Join(projDir, "README.md"))
	mustContain(t, readme, "My Service", "README.md renders the project name")
	if !exists(filepath.Join(projDir, "extra.txt")) {
		t.Error("new: feature_x=true must produce extra.txt (__if_feature_x__/)")
	}
	if !exists(filepath.Join(projDir, "advanced", "notes.md")) {
		t.Error("new: variant=advanced must produce advanced/notes.md (files rule)")
	}
	if !exists(filepath.Join(projDir, ".tplaiter", "project.yaml")) {
		t.Fatal("new: project marker .tplaiter/project.yaml is missing")
	}

	// 5. run test — manifest command (the skeleton's echo stub).
	mustRun(t, home, projDir, "run", "test")

	// 6. settings set: turn off feature_x — 3-way must remove extra.txt.
	mustRun(t, home, projDir, "settings", "set", "feature_x=false", "--yes")
	if exists(filepath.Join(projDir, "extra.txt")) {
		t.Error("settings set feature_x=false: extra.txt must be removed by the 3-way merge")
	}

	// 7. update --check — scans the tree for conflict markers; none should
	// remain after a clean settings set.
	mustRun(t, home, projDir, "update", "--check")

	// 8. stats --json — valid JSON with a stable schema (internal/stats:
	// FileStat.Score json:"score"), without checking a specific value.
	statsRes := mustRun(t, home, projDir, "stats", "--json")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(statsRes.Stdout), &parsed); err != nil {
		t.Fatalf("stats --json: invalid JSON: %v\nstdout:\n%s", err, statsRes.Stdout)
	}
	if _, ok := parsed["score"]; !ok {
		t.Errorf("stats --json: expected field %q, got: %v", "score", parsed)
	}

	// 9. projects list — the project is registered in the ~/.tplaiter registry.
	projList := mustRun(t, home, "", "projects", "list")
	mustContain(t, projList.Stdout, projDir, "projects list")
}
