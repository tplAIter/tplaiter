package state

import (
	"errors"
	"testing"
	"time"
)

func TestLoadIndex_MissingFileReturnsEmpty(t *testing.T) {
	home := t.TempDir()

	got, err := LoadIndex(home)
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}
	if got.Version != IndexVersion {
		t.Errorf("LoadIndex() Version = %d, want %d", got.Version, IndexVersion)
	}
	if got.Repos == nil || len(got.Repos) != 0 {
		t.Errorf("LoadIndex() Repos = %+v, want empty non-nil map", got.Repos)
	}
}

func TestIndex_SaveLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	generated := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	idx := NewIndex(generated)
	idx.Repos["example"] = []TemplateEntry{
		{
			Name:        "go-service",
			Version:     "1.4.0",
			Description: "сервис на Go",
			LabelsFlat:  map[string][]string{"lang": {"go"}, "infra": {"kafka", "postgres"}},
			Path:        "go-service/",
			Ref:         "v1.4.0",
		},
	}

	if err := SaveIndex(home, idx); err != nil {
		t.Fatalf("SaveIndex() error = %v", err)
	}

	got, err := LoadIndex(home)
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}
	if !got.GeneratedAt.Equal(generated) {
		t.Errorf("LoadIndex() GeneratedAt = %v, want %v", got.GeneratedAt, generated)
	}
	entries, ok := got.Repos["example"]
	if !ok || len(entries) != 1 || entries[0].Name != "go-service" {
		t.Fatalf("LoadIndex() Repos[example] = %+v", entries)
	}
	if entries[0].LabelsFlat["infra"][1] != "postgres" {
		t.Errorf("LoadIndex() LabelsFlat round-trip = %+v", entries[0].LabelsFlat)
	}
}

func TestLoadIndex_CorruptedYAMLReturnsErrIndexCorrupted(t *testing.T) {
	home := t.TempDir()
	writeRaw(t, home, indexFileName, "repos: {this is not: [valid\n")

	_, err := LoadIndex(home)
	if err == nil {
		t.Fatal("LoadIndex() with broken yaml = nil error, want ErrIndexCorrupted")
	}
	if !errors.Is(err, ErrIndexCorrupted) {
		t.Errorf("LoadIndex() error = %v, want errors.Is(err, ErrIndexCorrupted)", err)
	}
}

func TestLoadIndex_WrongShapeReturnsErrIndexCorrupted(t *testing.T) {
	home := t.TempDir()
	// YAML валиден, но repos — не map[string][]TemplateEntry.
	writeRaw(t, home, indexFileName, "version: 1\nrepos: \"not-a-map\"\n")

	_, err := LoadIndex(home)
	if !errors.Is(err, ErrIndexCorrupted) {
		t.Errorf("LoadIndex() error = %v, want errors.Is(err, ErrIndexCorrupted)", err)
	}
}

func TestLoadIndex_FutureVersionIsNotCorrupted(t *testing.T) {
	home := t.TempDir()
	writeRaw(t, home, indexFileName, "version: 999\nrepos: {}\n")

	_, err := LoadIndex(home)
	if err == nil {
		t.Fatal("LoadIndex() with future version = nil error, want error")
	}
	if errors.Is(err, ErrIndexCorrupted) {
		t.Error("LoadIndex() future-version error should NOT be ErrIndexCorrupted (it is a valid file, just newer)")
	}
}
