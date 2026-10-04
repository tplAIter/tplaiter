package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewMissingSourceRefusal is an executable source-admission oracle, separate
// from the tracked pending lifecycle acceptance scenarios that need signed fixtures.
func TestNewMissingSourceRefusal(t *testing.T) {
	requireGit(t)
	t.Parallel()
	home := newHome(t)
	origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v1.0.0")
	mustRun(t, home, "", "repo", "add", "example", "file://"+origin)
	t.Run("absent_target", func(t *testing.T) {
		requireNewMissingSource(t, home, "new", "example/single-basic", "Project", "--dir", filepath.Join(t.TempDir(), "proj"), "--defaults")
	})
	t.Run("foreign_target", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "proj")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(dir, "foreign.txt")
		if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireNewMissingSource(t, home, "new", "example/single-basic", "Project", "--dir", dir, "--defaults")
		if got := mustReadFile(t, marker); got != "preserve" {
			t.Fatal("missing-source refusal changed occupied target")
		}
	})
}
