package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// TestCheckoutLatestSeesFetchedCommits is a regression test: fetch in a
// non-bare clone moves only origin/<branch>, so checkout @latest must use the
// origin ref and see new commits after repo update.
func TestCheckoutLatestSeesFetchedCommits(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1\n")
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "fr", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// New commit in origin AFTER add.
	writeFile(t, filepath.Join(origin, "fresh.txt"), "new\n")
	commitAll(t, origin, "fresh commit")

	if err := m.Update(ctx, "fr"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	res, err := m.ResolveRef("fr/go-service@latest")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	fsys, cleanup, err := m.Checkout(ctx, res.RepoAlias, res.GitRef, res.Entry.Path)
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	defer func() { _ = cleanup() }()

	if _, err := fsys.Open("fresh.txt"); err != nil {
		t.Fatalf("checkout @latest does not see the fresh commit after update: %v", err)
	}
}

// TestUpdate_WorkingTreeAdvancesAfterFetch is a regression test: `repo update`
// used only `git fetch`, leaving the cache working tree at the old
// origin/<branch>. The on-disk cache and template.manifest.yaml used by scanRepo
// therefore stayed stale while the command reported success. Check both the
// clone HEAD and file contents directly, without Checkout masking the bug by
// using the origin ref.
func TestUpdate_WorkingTreeAdvancesAfterFetch(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "hello.txt"), "v1\n")
	commitAll(t, origin, "init")

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "fr", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	beforeHEAD := runGitOutput(t, origin, "rev-parse", "HEAD")

	// New commit in origin AFTER add changes both HEAD and hello.txt.
	writeFile(t, filepath.Join(origin, "hello.txt"), "v2\n")
	commitAll(t, origin, "fresh commit")
	afterHEAD := runGitOutput(t, origin, "rev-parse", "HEAD")
	if beforeHEAD == afterHEAD {
		t.Fatalf("origin HEAD did not change between commits")
	}

	if err := m.Update(ctx, "fr"); err != nil {
		t.Fatalf("Update: %v", err)
	}

	clone := m.cloneDir("fr")
	cloneHEAD := runGitOutput(t, clone, "rev-parse", "HEAD")
	if cloneHEAD != afterHEAD {
		t.Fatalf("cache clone HEAD did not move after update: clone=%s, origin=%s", cloneHEAD, afterHEAD)
	}

	got, err := os.ReadFile(filepath.Join(clone, "hello.txt"))
	if err != nil {
		t.Fatalf("reading hello.txt from the cache clone: %v", err)
	}
	if string(got) != "v2\n" {
		t.Fatalf("hello.txt in the cache clone after update = %q, expected %q (working tree was not updated)", got, "v2\n")
	}
}

// runGitOutput is like runGit but returns trimmed stdout (for rev-parse and
// similar one-line commands).
func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	res, err := gitExec.Run(context.Background(), "git", args, execx.Options{Dir: dir, Env: gitEnv()})
	if err != nil {
		t.Fatalf("git %v: %v\n%s%s", args, err, res.Stdout, res.Stderr)
	}
	return strings.TrimSpace(res.Stdout)
}
