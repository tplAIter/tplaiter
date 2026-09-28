package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHome_UsesEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, dir)

	got, err := Home()
	if err != nil {
		t.Fatalf("Home() error = %v", err)
	}
	if got != dir {
		t.Errorf("Home() = %q, want %q", got, dir)
	}
}

func TestHome_DefaultsUnderUserHomeDir(t *testing.T) {
	t.Setenv(HomeEnv, "")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir unavailable in this environment: %v", err)
	}

	got, err := Home()
	if err != nil {
		t.Fatalf("Home() error = %v", err)
	}
	want := filepath.Join(home, ".tplaiter")
	if got != want {
		t.Errorf("Home() = %q, want %q", got, want)
	}
}

func TestEnsureHome_CreatesSkeletonOnce(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "tplater-home") // does not exist before the first call
	t.Setenv(HomeEnv, root)

	home, created, err := EnsureHome()
	if err != nil {
		t.Fatalf("EnsureHome() error = %v", err)
	}
	if home != root {
		t.Errorf("EnsureHome() home = %q, want %q", home, root)
	}
	if !created {
		t.Error("EnsureHome() created = false on first call, want true")
	}
	if info, statErr := os.Stat(filepath.Join(root, "repos")); statErr != nil || !info.IsDir() {
		t.Errorf("EnsureHome() did not create repos/ subdir: stat error = %v", statErr)
	}

	// Second call: the directory exists, so created=false and nothing breaks.
	_, created2, err := EnsureHome()
	if err != nil {
		t.Fatalf("EnsureHome() second call error = %v", err)
	}
	if created2 {
		t.Error("EnsureHome() second call created = true, want false")
	}
}
