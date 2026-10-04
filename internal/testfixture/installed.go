package testfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ModuleRoot returns the root module directory (the one holding go.mod with
// the tplaiter module path), found by walking up from the working directory.
func ModuleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(raw), "module github.com/tplAIter/tplaiter\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("tplaiter module root not found")
		}
		dir = parent
	}
}
