package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/naming"
	"github.com/tplAIter/tplaiter/internal/project"
)

func writeMigrationHome(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationCLIPlanIsSealedAndDoesNotWrite(t *testing.T) {
	parent := t.TempDir()
	legacy, modern := filepath.Join(parent, "legacy"), filepath.Join(parent, "modern")
	writeMigrationHome(t, legacy)
	before, err := os.ReadFile(filepath.Join(legacy, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c := newMigrationCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"--root", "home=" + legacy + ":" + modern})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	var plan naming.Plan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if err := plan.Verify(); err != nil {
		t.Fatalf("CLI plan is not sealed: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(legacy, "state.yaml"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("plan changed source: %v", err)
	}
	if _, err := os.Stat(modern); !os.IsNotExist(err) {
		t.Fatalf("plan created destination: %v", err)
	}
}

func TestMigrationCLIApplyRejectsTamperedSealedPlanBeforeWrites(t *testing.T) {
	parent := t.TempDir()
	legacy, modern := filepath.Join(parent, "legacy"), filepath.Join(parent, "modern")
	writeMigrationHome(t, legacy)
	plan, err := naming.PlanHome(legacy, modern)
	if err != nil {
		t.Fatal(err)
	}
	plan.Roots[0].Entries[0].Bytes = []byte("tampered\n")
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "plan.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	c := newMigrationCmd()
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"--apply", "--plan", path, "--expected-digest", plan.Digest})
	if err := c.Execute(); err == nil {
		t.Fatal("tampered plan applied")
	}
	if _, err := os.Stat(modern); !os.IsNotExist(err) {
		t.Fatalf("tampered plan wrote destination: %v", err)
	}
	if info, err := os.Stat(legacy); err != nil || !info.IsDir() {
		t.Fatalf("tampered plan changed source: %v", err)
	}
}

func TestProjectsListUsesRelocatedRegistryAfterMultiRootMigration(t *testing.T) {
	parent := t.TempDir()
	oldHome, newHome := filepath.Join(parent, "old-home"), filepath.Join(parent, "new-home")
	writeMigrationHome(t, oldHome)
	oldPath, newPath := filepath.Join(parent, "old"), filepath.Join(parent, "moved")
	registry := []byte("version: 1\nitems:\n- id: moved\n  path: " + oldPath + "\n  template: {repo: r, name: n, version: v}\n  createdAt: 2020-01-01T00:00:00Z\n  lastSeenAt: 2020-01-01T00:00:00Z\n  baselineSHA: abc\n")
	if err := os.WriteFile(filepath.Join(oldHome, "projects.yaml"), registry, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(newPath, naming.LegacyProjectDir)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: moved\nbaseline: .tplater/baseline.json\n")
	if err := os.WriteFile(filepath.Join(legacy, "project.yaml"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "baseline.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := naming.PlanRoots([]naming.Root{{Kind: "home", SourceRoot: oldHome, DestinationRoot: newHome, Relocations: []naming.Relocation{{ID: "moved", OldPath: oldPath, NewPath: newPath}}}, {Kind: "project", SourceRoot: legacy, DestinationRoot: filepath.Join(newPath, naming.ProjectDir)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := naming.Apply(p); err != nil {
		t.Fatal(err)
	}
	if root, _, err := project.FindRoot(newPath); err != nil || root != newPath {
		t.Fatalf("new CLI project discovery failed: root=%q err=%v", root, err)
	}
	t.Setenv(naming.HomeEnv, newHome)
	t.Setenv(naming.LegacyHomeEnv, newHome)
	t.Setenv("HOME", filepath.Join(parent, "synthetic-home"))
	c := newProjectsListCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(newPath)) {
		t.Fatalf("new CLI did not use relocated registry: %s", out.String())
	}
}
