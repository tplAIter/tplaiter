package projectsync

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/state"
)

// writeMarker creates a minimally valid .tplaiter/project.yaml accepted by
// manifest.LoadProject, in the same format used by internal/project/locate_test.go fixtures.
func writeMarker(t *testing.T, dir, id, repo, name, version string) {
	t.Helper()
	tplDir := filepath.Join(dir, ".tplaiter")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", tplDir, err)
	}
	content := fmt.Sprintf(
		"apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: %s\ntemplate:\n  repo: %s\n  name: %s\n  version: %s\n",
		id, repo, name, version,
	)
	if err := os.WriteFile(filepath.Join(dir, project.MarkerRelPath), []byte(content), 0o644); err != nil {
		t.Fatalf("write project.yaml: %v", err)
	}
}

// writeBaseline writes .tplaiter/baseline.json with the supplied content and
// returns its hexadecimal SHA-256, the expected baselineSHA.
func writeBaseline(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(engine.BaselineRelPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write baseline.json: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// cleanPath resolves symlinks (macOS: /tmp -> /private/tmp) for stable path
// comparison, as required by internal/project/locate_test.go too.
func cleanPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", p, err)
	}
	return resolved
}

func mustFindByID(t *testing.T, home, id string) state.ProjectRef {
	t.Helper()
	projects, err := state.LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	ref, ok := projects.FindByID(id)
	if !ok {
		t.Fatalf("LoadProjects() не содержит записи с id %q, items=%+v", id, projects.Items)
	}
	return ref
}

func TestSyncCurrent_OutsideProject_NoOp(t *testing.T) {
	// home deliberately does not exist: the no-op must not try to create or lock
	// it, because it returns before accessing home.
	home := filepath.Join(t.TempDir(), "does-not-exist")
	cwd := t.TempDir() // No .tplaiter/project.yaml inside.

	if err := SyncCurrent(home, cwd, time.Now()); err != nil {
		t.Fatalf("SyncCurrent() вне проекта error = %v, want nil", err)
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("SyncCurrent() вне проекта создал home %s, want no-op", home)
	}
}

func TestSyncCurrent_MovedDirectory_UpdatesPathKeepsCreatedAtAndTemplate(t *testing.T) {
	home := t.TempDir()
	base := t.TempDir()
	oldPath := filepath.Join(base, "old-location")
	if err := os.MkdirAll(oldPath, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMarker(t, oldPath, "proj-1", "example", "go-service", "1.4.0")
	sha := writeBaseline(t, oldPath, `{"schema":1}`)

	created := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	seed := state.DefaultProjects()
	seed.Upsert(state.ProjectRef{
		ID:          "proj-1",
		Path:        oldPath,
		Template:    state.TemplateSelection{Repo: "example", Name: "go-service", Version: "1.4.0"},
		CreatedAt:   created,
		LastSeenAt:  created,
		BaselineSHA: sha,
	})
	if err := state.SaveProjects(home, seed); err != nil {
		t.Fatalf("SaveProjects() seed error = %v", err)
	}

	newPath := filepath.Join(base, "new-location")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("os.Rename() error = %v", err)
	}

	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	if err := SyncCurrent(home, newPath, now); err != nil {
		t.Fatalf("SyncCurrent() error = %v", err)
	}

	ref := mustFindByID(t, home, "proj-1")
	if cleanPath(t, ref.Path) != cleanPath(t, newPath) {
		t.Errorf("Path = %q, want %q (переезд каталога не отследился)", ref.Path, newPath)
	}
	if !ref.LastSeenAt.Equal(now) {
		t.Errorf("LastSeenAt = %v, want %v", ref.LastSeenAt, now)
	}
	if !ref.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v (не должен трогаться при обновлении)", ref.CreatedAt, created)
	}
	if ref.Template != (state.TemplateSelection{Repo: "example", Name: "go-service", Version: "1.4.0"}) {
		t.Errorf("Template = %+v, не должен трогаться при обновлении", ref.Template)
	}
	if ref.BaselineSHA != sha {
		t.Errorf("BaselineSHA = %q, want %q (baseline.json не менялся)", ref.BaselineSHA, sha)
	}
}

func TestSyncCurrent_UnregisteredClone_AutoRegisters(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	writeMarker(t, dir, "proj-clone", "example", "python-service", "2.0.0")
	sha := writeBaseline(t, dir, `{"schema":1,"templateVersion":"2.0.0"}`)

	// The registry exists but is empty: it has no "proj-clone" entry.
	if err := state.SaveProjects(home, state.DefaultProjects()); err != nil {
		t.Fatalf("SaveProjects() error = %v", err)
	}

	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	if err := SyncCurrent(home, dir, now); err != nil {
		t.Fatalf("SyncCurrent() error = %v", err)
	}

	ref := mustFindByID(t, home, "proj-clone")
	if cleanPath(t, ref.Path) != cleanPath(t, dir) {
		t.Errorf("Path = %q, want %q", ref.Path, dir)
	}
	wantTemplate := state.TemplateSelection{Repo: "example", Name: "python-service", Version: "2.0.0"}
	if ref.Template != wantTemplate {
		t.Errorf("Template = %+v, want %+v (из .tplaiter/project.yaml)", ref.Template, wantTemplate)
	}
	if !ref.CreatedAt.Equal(now) || !ref.LastSeenAt.Equal(now) {
		t.Errorf("CreatedAt/LastSeenAt = %v/%v, want оба = %v (первая регистрация)", ref.CreatedAt, ref.LastSeenAt, now)
	}
	if ref.BaselineSHA != sha {
		t.Errorf("BaselineSHA = %q, want %q", ref.BaselineSHA, sha)
	}
}

func TestSyncCurrent_BaselineSHAMismatch_Updates(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	writeMarker(t, dir, "proj-drift", "example", "go-service", "1.4.0")
	// baseline.json on disk is already newer than the registry knows, as if an
	// update had run on another machine without this registry participating.
	newSHA := writeBaseline(t, dir, `{"schema":1,"templateVersion":"1.5.0"}`)

	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldSeen := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seed := state.DefaultProjects()
	seed.Upsert(state.ProjectRef{
		ID:          "proj-drift",
		Path:        dir,
		Template:    state.TemplateSelection{Repo: "example", Name: "go-service", Version: "1.4.0"},
		CreatedAt:   created,
		LastSeenAt:  oldSeen,
		BaselineSHA: "stale-sha-from-old-machine",
	})
	if err := state.SaveProjects(home, seed); err != nil {
		t.Fatalf("SaveProjects() error = %v", err)
	}

	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	if err := SyncCurrent(home, dir, now); err != nil {
		t.Fatalf("SyncCurrent() error = %v", err)
	}

	ref := mustFindByID(t, home, "proj-drift")
	if ref.BaselineSHA != newSHA {
		t.Errorf("BaselineSHA = %q, want %q (расхождение должно обновиться)", ref.BaselineSHA, newSHA)
	}
	if !ref.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, не должен трогаться", ref.CreatedAt)
	}
	if !ref.LastSeenAt.Equal(now) {
		t.Errorf("LastSeenAt = %v, want %v", ref.LastSeenAt, now)
	}
}

func TestSyncCurrent_BrokenProjectYAML_ReturnsErrorNotPanics(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	tplDir := filepath.Join(dir, ".tplaiter")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// kind is not Project: LoadProject must reject it and FindRoot must return an
	// error other than ErrNotInProject.
	broken := "apiVersion: tplater.dev/v1alpha1\nkind: Template\nid: broken\n"
	if err := os.WriteFile(filepath.Join(tplDir, "project.yaml"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	err := SyncCurrent(home, dir, time.Now()) // Must not panic.
	if err == nil {
		t.Fatal("SyncCurrent() error = nil, want ошибку разбора маркера")
	}
	if errors.Is(err, project.ErrNotInProject) {
		t.Errorf("SyncCurrent() error = %v, не должен быть ErrNotInProject (маркер найден, но битый)", err)
	}
}
