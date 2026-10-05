package state

import (
	"strings"
	"testing"
)

func TestLoadConfig_MissingFileReturnsDefault(t *testing.T) {
	home := t.TempDir()

	got, err := LoadConfig(home)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	want := DefaultConfig()
	if got.Version != want.Version || len(got.Repos) != 0 || got.Updates != want.Updates {
		t.Errorf("LoadConfig() = %+v, want default %+v", got, want)
	}
	if !got.Updates.Check {
		t.Error("DefaultConfig().Updates.Check = false, want true")
	}
}

func TestConfig_SaveLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	cfg := Config{
		Version: ConfigVersion,
		Repos: []RepoRef{
			{Alias: "example", URL: "https://github.com/tplAIter/template-go.git", Branch: "main", Type: RepoKindGitLab},
			{Alias: "oss", URL: "https://github.com/example/tpl.git", Type: RepoKindGitHub},
		},
		Updates: UpdatesSettings{Check: false},
	}

	if err := SaveConfig(home, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	got, err := LoadConfig(home)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(got.Repos) != 2 || got.Repos[0] != cfg.Repos[0] || got.Repos[1] != cfg.Repos[1] {
		t.Errorf("LoadConfig() Repos = %+v, want %+v", got.Repos, cfg.Repos)
	}
	if got.Updates.Check {
		t.Error("LoadConfig() Updates.Check = true, want false (round-trip)")
	}
}

func TestLoadConfig_FutureVersionErrors(t *testing.T) {
	home := t.TempDir()
	writeRaw(t, home, configFileName, "version: 999\nrepos: []\n")

	_, err := LoadConfig(home)
	if err == nil {
		t.Fatal("LoadConfig() with future version = nil error, want error")
	}
	if !strings.Contains(err.Error(), "update tplaiter") {
		t.Errorf("LoadConfig() error = %q, want mention of \"update tplaiter\"", err)
	}
}

func TestLoadConfig_UnparseableYAMLErrors(t *testing.T) {
	home := t.TempDir()
	writeRaw(t, home, configFileName, "not: valid: yaml: [")

	if _, err := LoadConfig(home); err == nil {
		t.Fatal("LoadConfig() with broken yaml = nil error, want error")
	}
}

func TestSaveConfig_AtomicNoLeftoverTempFiles(t *testing.T) {
	home := t.TempDir()
	if err := SaveConfig(home, DefaultConfig()); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	entries, err := readDirNames(home)
	if err != nil {
		t.Fatalf("readDirNames: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e, ".tmp-") {
			t.Errorf("leftover temp file after SaveConfig: %s", e)
		}
	}
}
