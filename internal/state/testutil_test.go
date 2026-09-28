package state

import (
	"os"
	"path/filepath"
	"testing"
)

// readDirNames returns file and directory names directly inside dir (without
// recursion), used to ensure writeFileAtomic leaves no temporary files after a
// successful write.
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// writeRaw writes content directly to name inside home (bypassing Save*) so
// tests can supply corrupt, future, or old YAML and verify Load* behavior.
func writeRaw(t *testing.T, home, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writeRaw(%q): %v", name, err)
	}
}
