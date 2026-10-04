package repo

import (
	"context"
	"io/fs"
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

func TestCheckoutRejectsTemplatePathEscapingAtRequestedRef(t *testing.T) {
	requireGit(t)
	ctx := context.Background()

	origin := initOrigin(t)
	templateDir := filepath.Join(origin, "template")
	writeFile(t, filepath.Join(templateDir, templateManifestName), singleManifest)
	writeFile(t, filepath.Join(templateDir, "hello.txt"), "safe\n")
	commitAll(t, origin, "safe template")
	mainCommit := runGitOutput(t, origin, "rev-parse", "HEAD")

	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside\n")
	if err := os.RemoveAll(templateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, templateDir); err != nil {
		t.Fatal(err)
	}
	commitAll(t, origin, "malicious template ref")
	runGit(t, origin, "tag", "malicious")
	runGit(t, origin, "reset", "--hard", mainCommit)

	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "escape", URL: fileURL(origin)}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, _, err := m.Checkout(ctx, "escape", "malicious", "template"); err == nil || !strings.Contains(err.Error(), "escapes checkout root") {
		t.Fatalf("Checkout malicious ref error=%v, want checkout-root confinement error", err)
	}
}

func TestCheckoutConfinesDescendantSymlinksAtOtherRef(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, "template", templateManifestName), singleManifest)
	commitAll(t, origin, "safe main")
	main := runGitOutput(t, origin, "rev-parse", "HEAD")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "canary"), "external canary")
	for _, name := range []string{templateManifestName, "file.txt"} {
		p := filepath.Join(origin, "template", name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "canary"), p); err != nil {
			t.Fatal(err)
		}
	}
	commitAll(t, origin, "escaping descendants")
	runGit(t, origin, "tag", "descendants")
	runGit(t, origin, "reset", "--hard", main)
	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "descendants", URL: fileURL(origin)}); err != nil {
		t.Fatal(err)
	}
	fsys, cleanup, err := m.Checkout(ctx, "descendants", "descendants", "template")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	for _, name := range []string{templateManifestName, "file.txt"} {
		if b, err := fs.ReadFile(fsys, name); err == nil {
			t.Fatalf("escaping descendant %s read %q", name, b)
		}
	}
}

func TestCheckoutRetainsDirectoryAfterReplacement(t *testing.T) {
	requireGit(t)
	ctx := context.Background()
	origin := initOrigin(t)
	writeFile(t, filepath.Join(origin, "template", templateManifestName), singleManifest)
	writeFile(t, filepath.Join(origin, "template", "file.txt"), "original")
	commitAll(t, origin, "safe template")
	m := newIntegrationManager(t)
	if err := m.Add(ctx, AddOptions{Alias: "replacement", URL: fileURL(origin)}); err != nil {
		t.Fatal(err)
	}
	fsys, cleanup, err := m.Checkout(ctx, "replacement", "main", "template")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	var wt string
	for _, line := range strings.Split(runGitOutput(t, m.cloneDir("replacement"), "worktree", "list", "--porcelain"), "\n") {
		if strings.HasPrefix(line, "worktree ") && strings.Contains(line, "tplater-checkout-replacement-") {
			wt = strings.TrimPrefix(line, "worktree ")
		}
	}
	if wt == "" {
		t.Fatal("checkout worktree not found")
	}
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "file.txt"), "external canary")
	p := filepath.Join(wt, "template")
	if err := os.Rename(p, p+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	if b, err := fs.ReadFile(fsys, "file.txt"); err != nil || string(b) != "original" {
		t.Fatalf("held checkout read %q, %v", b, err)
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
