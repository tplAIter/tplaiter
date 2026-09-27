//go:build darwin || linux

package trustload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureReadRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(realDir, "record.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "final.json")
	if err := os.Symlink(file, final); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadFile(final, maxDocument); err == nil {
		t.Fatal("accepted final symlink")
	}
	parent := filepath.Join(root, "parent")
	if err := os.Symlink(realDir, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadFile(filepath.Join(parent, "record.json"), maxDocument); err == nil {
		t.Fatal("accepted parent symlink")
	}
}

func TestSecureReadDoesNotLeakDescriptorsOnOpenFailures(t *testing.T) {
	root := t.TempDir()
	before, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skip(err)
	}
	for i := 0; i < 128; i++ {
		if _, err := secureReadFile(filepath.Join(root, "missing", "record.json"), maxDocument); err == nil {
			t.Fatal("accepted missing path")
		}
	}
	after, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skip(err)
	}
	if len(after) > len(before)+1 {
		t.Fatalf("descriptor leak: before=%d after=%d", len(before), len(after))
	}
}
