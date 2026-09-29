package readonlysnapshot

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProjectSnapshotHashesSortedAndSkipsLedgers(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".tplaiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "apiVersion: tplater.dev/v1\nid: project-1\n"
	if err := os.WriteFile(filepath.Join(root, ".tplaiter", "project.yaml"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "z.txt"), []byte("z"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	if s.ProjectID != "project-1" || len(s.Tracked) != 2 {
		t.Fatalf("snapshot=%#v", s)
	}
	if s.Tracked[0].Path != "a.txt" || s.Tracked[1].Path != "z.txt" {
		t.Fatalf("order=%#v", s.Tracked)
	}
}

func TestProjectSnapshotBindsIndexTrackedAndUntrackedContent(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".tplaiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".tplaiter", "project.yaml"), []byte("id: project-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "add", ".tplaiter/project.yaml", "tracked.txt")
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("untracked-v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Head != "" || first.IndexSHA256 == "" || len(first.Untracked) != 1 {
		t.Fatalf("first snapshot=%#v", first)
	}
	if first.Untracked[0].Path != "untracked.txt" || first.Untracked[0].Mode != 0o600 || first.Untracked[0].Kind != "file" {
		t.Fatalf("untracked evidence=%#v", first.Untracked)
	}

	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("untracked-v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "untracked.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Untracked[0].SHA256 == second.Untracked[0].SHA256 || first.Untracked[0].Mode == second.Untracked[0].Mode {
		t.Fatalf("untracked content/mode was not rebound: before=%#v after=%#v", first.Untracked, second.Untracked)
	}

	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked-v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt")
	third, err := Project(root)
	if err != nil {
		t.Fatal(err)
	}
	if second.IndexSHA256 == third.IndexSHA256 {
		t.Fatal("staged index evidence did not change")
	}
	if digestFor(second.Tracked, "tracked.txt") == digestFor(third.Tracked, "tracked.txt") {
		t.Fatal("tracked content evidence did not change")
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	argv := append([]string{"-C", root, "-c", "credential.helper=", "-c", "core.askPass="}, args...)
	command := exec.Command("git", argv...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func digestFor(items []FileDigest, path string) string {
	for _, item := range items {
		if item.Path == path {
			return item.SHA256
		}
	}
	return ""
}
