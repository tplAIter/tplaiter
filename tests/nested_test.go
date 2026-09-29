package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNestedTemplates covers repository discovery of a provider-shaped
// repository (U05): a root template plus nested templates are indexed and
// listed, lint-template validates all of them, and unsafe or ambiguous
// repositories are rejected with typed errors without being registered.
func TestNestedTemplates(t *testing.T) {
	requireGit(t)
	t.Parallel()

	t.Run("root and nested are listed", func(t *testing.T) {
		t.Parallel()
		home := newHome(t)
		origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "nested-provider"), "v0.1.0", "service/v0.1.0")

		mustRun(t, home, "", "repo", "add", "provider", "file://"+origin)
		list := mustRun(t, home, "", "template", "list")
		for _, name := range []string{"provider-base", "service", "worker"} {
			mustContain(t, list.Stdout, name, "template list")
		}
		repoOnly := mustRun(t, home, "", "template", "list", "--repo", "provider", "--name", "service")
		mustContain(t, repoOnly.Stdout, "service", "template list --name service")
		if strings.Contains(repoOnly.Stdout, "worker") {
			t.Errorf("template list --name service must not list worker:\n%s", repoOnly.Stdout)
		}
	})

	t.Run("lint-template covers nested templates", func(t *testing.T) {
		t.Parallel()
		home := newHome(t)
		res := mustRun(t, home, filepath.Join(fixturesDir(t), "nested-provider"), "lint-template")
		for _, rel := range []string{"bootstrap/template-repository/templates/service", "templates/worker"} {
			mustContain(t, res.Stdout, rel, "lint-template")
		}
	})

	t.Run("escaping template path is rejected", func(t *testing.T) {
		t.Parallel()
		home := newHome(t)
		origin := filepath.Join(t.TempDir(), "origin")
		copyTree(t, filepath.Join(fixturesDir(t), "nested-provider"), origin)
		writeRepoManifest(t, origin, "../outside")
		initGitOrigin(t, origin)

		res := run(t, home, "", "repo", "add", "escape", "file://"+origin)
		if res.ExitCode == 0 {
			t.Fatal("repo add with an escaping templates[].path must fail")
		}
		mustContain(t, res.Stderr+res.Stdout, "TPL-E-REPO-PATH-ESCAPE", "repo add escape")
		assertNotRegistered(t, home, "escape")
	})

	t.Run("duplicate template name is rejected", func(t *testing.T) {
		t.Parallel()
		home := newHome(t)
		origin := filepath.Join(t.TempDir(), "origin")
		copyTree(t, filepath.Join(fixturesDir(t), "nested-provider"), origin)
		dup := filepath.Join(origin, "templates", "worker-copy")
		copyTree(t, filepath.Join(origin, "templates", "worker"), dup)
		initGitOrigin(t, origin)

		res := run(t, home, "", "repo", "add", "dup", "file://"+origin)
		if res.ExitCode == 0 {
			t.Fatal("repo add with a duplicate template name must fail")
		}
		mustContain(t, res.Stderr+res.Stdout, "TPL-E-REPO-DUP-NAME", "repo add duplicate")
		assertNotRegistered(t, home, "dup")
	})
}

func writeRepoManifest(t *testing.T, dir string, paths ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: tplater.dev/v1alpha1\nkind: Repository\nmetadata: {name: provider}\ntemplates:\n")
	for _, p := range paths {
		b.WriteString("  - path: '" + p + "'\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "repo.manifest.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertNotRegistered(t *testing.T, home, alias string) {
	t.Helper()
	list := mustRun(t, home, "", "repo", "list")
	if strings.Contains(list.Stdout, alias) {
		t.Errorf("rejected repository %q must not be registered:\n%s", alias, list.Stdout)
	}
	if exists(filepath.Join(home, "repos", alias)) {
		t.Errorf("rejected repository %q left a clone behind", alias)
	}
}
