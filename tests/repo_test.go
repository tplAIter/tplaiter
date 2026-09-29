package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoLifecycle runs template repository management (scenario 2,
// implementation requirement): add an invalid path -> error; duplicate alias
// -> error; update; remove.
func TestRepoLifecycle(t *testing.T) {
	requireGit(t)
	t.Parallel()

	home := newHome(t)
	origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v1.0.0")

	// add an invalid path (local file:// pointing to a nonexistent directory) —
	// git clone must fail and the repository must not be registered.
	badPath := filepath.Join(t.TempDir(), "does-not-exist")
	bad := run(t, home, "", "repo", "add", "bad", "file://"+badPath)
	if bad.ExitCode == 0 {
		t.Fatalf("repo add with a non-existent path: expected a non-zero exit, got 0\nstdout:\n%s", bad.Stdout)
	}
	listAfterBad := mustRun(t, home, "", "repo", "list")
	if strings.Contains(listAfterBad.Stdout, "bad") {
		t.Errorf("repo add with a non-existent path must NOT register the alias: %s", listAfterBad.Stdout)
	}

	// Add a valid repository under alias "dup".
	mustRun(t, home, "", "repo", "add", "dup", "file://"+origin)

	// Reusing the same alias with ANY URL is an error.
	dupAgain := run(t, home, "", "repo", "add", "dup", "file://"+origin)
	if dupAgain.ExitCode == 0 {
		t.Fatalf("repo add with a taken alias: expected a non-zero exit, got 0")
	}
	mustContain(t, dupAgain.Stderr+dupAgain.Stdout, "dup", "repo add with a taken alias")

	// update: git fetch + reindexing — on a file:// repository with no new
	// commits, it should simply complete cleanly.
	mustRun(t, home, "", "repo", "update", "dup")

	// remove: the alias disappears from the repository list.
	mustRun(t, home, "", "repo", "remove", "dup")
	afterRemove := mustRun(t, home, "", "repo", "list")
	if strings.Contains(afterRemove.Stdout, "dup") {
		t.Errorf("repo remove: alias %q is still listed:\n%s", "dup", afterRemove.Stdout)
	}
	if exists(filepath.Join(home, "repos", "dup")) {
		t.Error("repo remove: clone directory repos/dup must be removed")
	}
}
