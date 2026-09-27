package gen

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWorkspaceUseDirs — go.work-монорепо собирается помодульно (находка CG-4).
func TestWorkspaceUseDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if got, err := workspaceUseDirs(dir); err != nil || got != nil {
		t.Fatalf("без go.work ожидается nil,nil: %v %v", got, err)
	}

	work := "go 1.26\n\nuse (\n\t./services/a\n\t./services/b\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte(work), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := workspaceUseDirs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "./services/a" || got[1] != "./services/b" {
		t.Fatalf("use-директории: %v", got)
	}
}

func TestWorkspaceUseDirsRejectsUnsafePaths(t *testing.T) {
	for _, use := range []string{"/absolute/module", "../outside"} {
		t.Run(use, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte("go 1.26\n\nuse (\n\t"+use+"\n)\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := workspaceUseDirs(dir); !errors.Is(err, errWorkspacePathUnsafe) {
				t.Fatalf("workspaceUseDirs(%q) error = %v", use, err)
			}
		})
	}
}

func TestWorkspaceUseDirsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte("go 1.26\n\nuse (\n\t./linked\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workspaceUseDirs(dir); !errors.Is(err, errWorkspacePathUnsafe) {
		t.Fatalf("symlink workspace path error = %v", err)
	}
}

func TestWorkspaceUseDirsRejectsRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "module"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte("go 1.26\n\nuse (\n\t./module\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workspaceUseDirs(dir); !errors.Is(err, errWorkspacePathUnsafe) {
		t.Fatalf("regular-file workspace path error = %v", err)
	}
}
