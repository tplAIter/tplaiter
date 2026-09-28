package e2e

import (
	"path/filepath"
	"testing"
)

// TestMultiRepoAmbiguous runs the multi-template repository pipeline and
// short-name ambiguity (scenario 4, implementation requirement): repo add
// testdata/fixtures/multi (alpha+beta) under one alias, then a SECOND
// repository containing a template with the SAME name "alpha" — a short
// reference without the repo/ prefix must return an ambiguity error listing
// candidates (internal/repo/resolve.go:findTemplate).
func TestMultiRepoAmbiguous(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	fixtures := fixturesDir(t)

	// multi1: testdata/fixtures/multi repository fixture (repo.manifest.yaml,
	// alpha/beta templates) — tags are namespaced as (<name>/vX.Y.Z).
	multiOrigin := filepath.Join(t.TempDir(), "multi-origin")
	copyTree(t, filepath.Join(fixtures, "multi"), multiOrigin)
	initGitOrigin(t, multiOrigin, "alpha/v1.0.0", "beta/v1.0.0")
	mustRun(t, home, "", "repo", "add", "multi1", "file://"+multiOrigin)

	// multi2: a single-template repository whose ONLY template is also called
	// "alpha" (a copy of testdata/fixtures/multi/alpha as the repository root) —
	// creates short-name "alpha" ambiguity between multi1 and multi2.
	alphaOnlyOrigin := buildSingleOrigin(t, filepath.Join(fixtures, "multi", "alpha"), "v1.0.0")
	mustRun(t, home, "", "repo", "add", "multi2", "file://"+alphaOnlyOrigin)

	// The catalog lists both alpha templates (one in each repository) plus beta.
	list := mustRun(t, home, "", "template", "list")
	mustContain(t, list.Stdout, "alpha", "template list (multi)")
	mustContain(t, list.Stdout, "beta", "template list (multi)")

	// Short name "alpha" is ambiguous — an error listing "<alias>/alpha"
	// for each match.
	ambiguous := run(t, home, "", "template", "show", "alpha")
	if ambiguous.ExitCode == 0 {
		t.Fatalf("template show alpha: ожидалась ошибка неоднозначности, получен exit 0\n%s", ambiguous.Stdout)
	}
	combined := ambiguous.Stderr + ambiguous.Stdout
	mustContain(t, combined, "multi1/alpha", "неоднозначное имя alpha")
	mustContain(t, combined, "multi2/alpha", "неоднозначное имя alpha")

	// Qualifying with repo/ removes the ambiguity.
	mustRun(t, home, "", "template", "show", "multi1/alpha")
	mustRun(t, home, "", "template", "show", "multi2/alpha")

	// Full multi pipeline: `new` from the beta template (a unique, unambiguous
	// name) successfully creates a project.
	projDir := filepath.Join(t.TempDir(), "beta-proj")
	mustRun(t, home, "", "new", "multi1/beta", "Beta Project", "--dir", projDir, "--defaults")
	if !exists(filepath.Join(projDir, ".tplaiter", "project.yaml")) {
		t.Error("new multi1/beta: отсутствует проектный маркер")
	}
}
