package state

import (
	"testing"
	"time"
)

func TestLoadProjects_MissingFileReturnsDefault(t *testing.T) {
	home := t.TempDir()

	got, err := LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if got.Version != ProjectsVersion || len(got.Items) != 0 {
		t.Errorf("LoadProjects() = %+v, want empty default", got)
	}
}

func TestProjects_SaveLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	created := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	p := DefaultProjects()
	p.Items = append(p.Items, ProjectRef{
		ID:          "8f3a",
		Path:        "/workspace/uber",
		Template:    TemplateSelection{Repo: "example", Name: "go-service", Version: "1.4.0"},
		CreatedAt:   created,
		LastSeenAt:  created,
		BaselineSHA: "c0ffee",
	})

	if err := SaveProjects(home, p); err != nil {
		t.Fatalf("SaveProjects() error = %v", err)
	}

	got, err := LoadProjects(home)
	if err != nil {
		t.Fatalf("LoadProjects() error = %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].ID != "8f3a" || got.Items[0].BaselineSHA != "c0ffee" {
		t.Fatalf("LoadProjects() = %+v", got.Items)
	}
	if !got.Items[0].CreatedAt.Equal(created) {
		t.Errorf("LoadProjects() CreatedAt = %v, want %v", got.Items[0].CreatedAt, created)
	}
}

func TestProjects_UpsertInsertsNew(t *testing.T) {
	var p Projects
	ref := ProjectRef{ID: "a", Path: "/p/a", Template: TemplateSelection{Repo: "example", Name: "svc"}}
	p.Upsert(ref)

	if len(p.Items) != 1 || p.Items[0] != ref {
		t.Errorf("Upsert() on empty registry = %+v, want [%+v]", p.Items, ref)
	}
}

func TestProjects_UpsertUpdatesExistingByID(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := created.Add(24 * time.Hour)
	var p Projects
	p.Upsert(ProjectRef{
		ID:         "a",
		Path:       "/old/path",
		Template:   TemplateSelection{Repo: "example", Name: "svc", Version: "1.0.0"},
		CreatedAt:  created,
		LastSeenAt: created,
	})

	p.Upsert(ProjectRef{
		ID:          "a",
		Path:        "/new/path", // проект переехал
		LastSeenAt:  later,
		BaselineSHA: "deadbeef",
		// Template/CreatedAt намеренно не передаём новыми значениями —
		// Upsert должен сохранить исходные (см. doc-комментарий Upsert).
	})

	if len(p.Items) != 1 {
		t.Fatalf("Upsert() should update in place, got %d items", len(p.Items))
	}
	got := p.Items[0]
	if got.Path != "/new/path" {
		t.Errorf("Upsert() Path = %q, want /new/path", got.Path)
	}
	if !got.LastSeenAt.Equal(later) {
		t.Errorf("Upsert() LastSeenAt = %v, want %v", got.LastSeenAt, later)
	}
	if got.BaselineSHA != "deadbeef" {
		t.Errorf("Upsert() BaselineSHA = %q, want deadbeef", got.BaselineSHA)
	}
	if got.Template.Version != "1.0.0" {
		t.Errorf("Upsert() Template.Version = %q, want unchanged 1.0.0", got.Template.Version)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("Upsert() CreatedAt = %v, want unchanged %v", got.CreatedAt, created)
	}
}

func TestProjects_FindByID(t *testing.T) {
	var p Projects
	p.Upsert(ProjectRef{ID: "a", Path: "/p/a"})

	if _, ok := p.FindByID("missing"); ok {
		t.Error("FindByID(missing) ok = true, want false")
	}
	got, ok := p.FindByID("a")
	if !ok || got.Path != "/p/a" {
		t.Errorf("FindByID(a) = %+v, %v", got, ok)
	}
}

func TestProjects_Remove(t *testing.T) {
	var p Projects
	p.Upsert(ProjectRef{ID: "a"})
	p.Upsert(ProjectRef{ID: "b"})

	if !p.Remove("a") {
		t.Error("Remove(a) = false, want true")
	}
	if p.Remove("a") {
		t.Error("Remove(a) second call = true, want false (already gone)")
	}
	if len(p.Items) != 1 || p.Items[0].ID != "b" {
		t.Errorf("Remove() left items = %+v, want only [b]", p.Items)
	}
}

func TestProjects_Prune(t *testing.T) {
	var p Projects
	p.Upsert(ProjectRef{ID: "a", Path: "/exists"})
	p.Upsert(ProjectRef{ID: "b", Path: "/missing"})
	p.Upsert(ProjectRef{ID: "c", Path: "/exists-too"})

	exists := func(path string) bool { return path != "/missing" }
	removed := p.Prune(exists)

	if len(removed) != 1 || removed[0].ID != "b" {
		t.Errorf("Prune() removed = %+v, want [b]", removed)
	}
	if len(p.Items) != 2 {
		t.Fatalf("Prune() left %d items, want 2", len(p.Items))
	}
	if _, ok := p.FindByID("b"); ok {
		t.Error("Prune() left b in registry")
	}
}

func TestProjects_PruneNothingToRemove(t *testing.T) {
	var p Projects
	p.Upsert(ProjectRef{ID: "a", Path: "/exists"})

	removed := p.Prune(func(string) bool { return true })
	if len(removed) != 0 {
		t.Errorf("Prune() removed = %+v, want none", removed)
	}
	if len(p.Items) != 1 {
		t.Errorf("Prune() should not touch items when nothing missing, got %+v", p.Items)
	}
}
