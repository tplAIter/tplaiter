package gen

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWorkspaceUseDirs — go.work-монорепо собирается помодульно (находка ).
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
