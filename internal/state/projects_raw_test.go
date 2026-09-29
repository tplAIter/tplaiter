package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectsRawRoundTripIsByteExactAndDurable(t *testing.T) {
	home := t.TempDir()
	if _, exists, _, err := ReadProjectsRaw(home); err != nil || exists {
		t.Fatalf("absent registry: exists=%v err=%v", exists, err)
	}
	raw := []byte("version: 1\nitems:\n- id: p\n  path: /workspace/p\n")
	if err := WriteProjectsRaw(home, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, exists, mode, err := ReadProjectsRaw(home)
	if err != nil || !exists || string(got) != string(raw) || mode != 0o600 {
		t.Fatalf("raw=%q exists=%v mode=%v err=%v", got, exists, mode, err)
	}
	decoded, err := DecodeProjectsRaw(got)
	if err != nil {
		t.Fatal(err)
	}
	if ref, ok := decoded.FindByID("p"); !ok || ref.Path != "/workspace/p" {
		t.Fatalf("decoded=%+v", decoded)
	}
	marshaled, err := MarshalProjects(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProjectsRaw(marshaled); err != nil {
		t.Fatal(err)
	}
	if ProjectsPath(home) != filepath.Join(home, "projects.yaml") {
		t.Fatalf("ProjectsPath=%s", ProjectsPath(home))
	}
	if err := RemoveProjectsRaw(home); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProjectsRaw(home); err != nil {
		t.Fatalf("remove is not idempotent: %v", err)
	}
}

func TestProjectsRawRefusesInvalidBytesAndSymlinks(t *testing.T) {
	home := t.TempDir()
	if err := WriteProjectsRaw(home, []byte("version: 99\n"), 0o600); err == nil {
		t.Fatal("future registry version written")
	}
	outside := filepath.Join(t.TempDir(), "projects.yaml")
	if err := os.WriteFile(outside, []byte("version: 1\nitems: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, ProjectsPath(home)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ReadProjectsRaw(home); err == nil {
		t.Fatal("symlinked registry was read")
	}
	if err := WriteProjectsRaw(home, []byte("version: 1\nitems: []\n"), 0o600); err == nil {
		t.Fatal("write through a symlinked registry")
	}
}
