package project

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// manifestFixture is the same fixture manifest used by
// internal/manifest/parse_test.go (../../testdata/manifest/full.yaml); reuse
// it instead of maintaining a copy.
const manifestFixture = "../../testdata/manifest/full.yaml"

func writeSnapshot(t *testing.T, root string) {
	t.Helper()
	data, err := os.ReadFile(manifestFixture)
	if err != nil {
		t.Fatalf("чтение фикстуры %s: %v", manifestFixture, err)
	}
	snapPath := filepath.Join(root, manifest.SnapshotRelPath)
	if err := os.MkdirAll(filepath.Dir(snapPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotSource_Happy(t *testing.T) {
	root := t.TempDir()
	writeSnapshot(t, root)

	src := SnapshotSource{Root: root}
	if src.Name() != "snapshot" {
		t.Errorf("Name() = %q, want %q", src.Name(), "snapshot")
	}

	tpl, err := src.Load(&manifest.Project{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tpl.Metadata.Name != "go-service" {
		t.Errorf("tpl.Metadata.Name = %q, want go-service", tpl.Metadata.Name)
	}
}

func TestSnapshotSource_Absent(t *testing.T) {
	root := t.TempDir()

	_, err := (SnapshotSource{Root: root}).Load(&manifest.Project{})
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestSnapshotSource_Corrupt(t *testing.T) {
	root := t.TempDir()
	snapPath := filepath.Join(root, manifest.SnapshotRelPath)
	if err := os.MkdirAll(filepath.Dir(snapPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapPath, []byte("not: valid: yaml: :::"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := (SnapshotSource{Root: root}).Load(&manifest.Project{})
	if err == nil {
		t.Fatal("ожидалась ошибка для битого снимка")
	}
	if errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("испорченный снимок не должен маскироваться под ErrSourceUnavailable: %v", err)
	}
}

func TestLoadManifestForProject_FallsBackToSnapshot(t *testing.T) {
	root := t.TempDir()
	writeSnapshot(t, root)

	proj := &manifest.Project{
		Template: manifest.ProjectTemplate{Repo: "example", Name: "go-service", Version: "1.4.0"},
	}
	tpl, source, err := LoadManifestForProject(root, proj, t.TempDir())
	if err != nil {
		t.Fatalf("LoadManifestForProject: %v", err)
	}
	if source != "snapshot" {
		t.Errorf("source = %q, want snapshot", source)
	}
	if tpl.Metadata.Name != "go-service" {
		t.Errorf("tpl.Metadata.Name = %q, want go-service", tpl.Metadata.Name)
	}
}

func TestLoadManifestForProject_NoSources(t *testing.T) {
	root := t.TempDir()
	proj := &manifest.Project{Template: manifest.ProjectTemplate{Repo: "example"}}

	_, _, err := LoadManifestForProject(root, proj, t.TempDir())
	if !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err = %v, want ErrNoManifest", err)
	}
}
