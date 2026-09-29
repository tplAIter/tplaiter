package project

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// writeProjectMarker creates .tplaiter/project.yaml in dir with the minimum
// valid content accepted by manifest.LoadProject.
func writeProjectMarker(t *testing.T, dir string) {
	t.Helper()
	tplDir := filepath.Join(dir, ".tplaiter")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", tplDir, err)
	}
	content := "apiVersion: tplater.dev/v1alpha1\n" +
		"kind: Project\n" +
		"id: test-id\n" +
		"template:\n  repo: example\n  name: go-service\n  version: 1.4.0\n"
	if err := os.WriteFile(filepath.Join(tplDir, "project.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write project.yaml: %v", err)
	}
}

// cleanPath resolves symlinks (macOS: /tmp -> /private/tmp) so paths returned
// by FindRoot compare consistently with expected paths.
func cleanPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", p, err)
	}
	return resolved
}

func TestFindRoot_AtRoot(t *testing.T) {
	root := t.TempDir()
	writeProjectMarker(t, root)
	t.Setenv("HOME", root)

	gotRoot, proj, err := FindRoot(root)
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if cleanPath(t, gotRoot) != cleanPath(t, root) {
		t.Errorf("root = %q, want %q", gotRoot, root)
	}
	if proj.ID != "test-id" {
		t.Errorf("proj.ID = %q, want test-id", proj.ID)
	}
}

func TestFindRoot_Deep(t *testing.T) {
	root := t.TempDir()
	writeProjectMarker(t, root)
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)

	gotRoot, proj, err := FindRoot(deep)
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if cleanPath(t, gotRoot) != cleanPath(t, root) {
		t.Errorf("root = %q, want %q", gotRoot, root)
	}
	if proj.Template.Name != "go-service" {
		t.Errorf("proj.Template.Name = %q", proj.Template.Name)
	}
}

func TestFindRoot_OutsideProject(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "somewhere", "else")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	_, _, err := FindRoot(dir)
	if !errors.Is(err, ErrNotInProject) {
		t.Fatalf("err = %v, want ErrNotInProject", err)
	}
}

// TestFindRoot_StopsAtHome verifies that the search does not walk above $HOME,
// even when a project marker exists in a parent of $HOME (for example, the
// user works in a tplater project somewhere in the home tree, while the
// parent of $HOME happens to contain another .tplaiter/project.yaml that must
// not be searched).
func TestFindRoot_StopsAtHome(t *testing.T) {
	sandbox := t.TempDir()
	writeProjectMarker(t, sandbox) // Marker ABOVE the future $HOME.

	home := filepath.Join(sandbox, "home")
	deep := filepath.Join(home, "work", "svc")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	_, _, err := FindRoot(deep)
	if !errors.Is(err, ErrNotInProject) {
		t.Fatalf("err = %v, want ErrNotInProject (a marker above $HOME must not be found)", err)
	}
}

// TestFindRoot_MarkerAtHomeItself verifies the boundary condition: $HOME is
// checked as the last directory before stopping rather than skipped.
func TestFindRoot_MarkerAtHomeItself(t *testing.T) {
	sandbox := t.TempDir()
	home := filepath.Join(sandbox, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectMarker(t, home)

	deep := filepath.Join(home, "work", "svc")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	gotRoot, _, err := FindRoot(deep)
	if err != nil {
		t.Fatalf("FindRoot: %v", err)
	}
	if cleanPath(t, gotRoot) != cleanPath(t, home) {
		t.Errorf("root = %q, want %q", gotRoot, home)
	}
}

func TestFindRoot_UsesModernMarkerAfterVerifiedProjectMigration(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, naming.LegacyProjectDir)
	modern := filepath.Join(root, naming.ProjectDir)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := "apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: migrated\nbaseline: .tplater/baseline.json\n"
	if err := os.WriteFile(filepath.Join(legacy, "project.yaml"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "baseline.json"), []byte("{\"schema\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := naming.PlanRoots([]naming.Root{{Kind: "project", SourceRoot: legacy, DestinationRoot: modern}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := naming.Apply(plan); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	got, proj, err := FindRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if cleanPath(t, got) != cleanPath(t, root) || proj.ID != "migrated" {
		t.Fatalf("FindRoot() = %q, %#v", got, proj)
	}
}

func TestFindRoot_RejectsUnreceiptedDualMarkers(t *testing.T) {
	root := t.TempDir()
	writeProjectMarker(t, root)
	if err := os.MkdirAll(filepath.Join(root, naming.LegacyProjectDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, LegacyMarkerRelPath), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	if _, _, err := FindRoot(root); err == nil {
		t.Fatal("unreceipted dual markers accepted")
	}
}

func TestFindRoot_RejectsInvalidNormalTombstoneReceiptStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root, legacy, modern, archive string, receipt []byte)
	}{
		{name: "missing receipt", mutate: func(t *testing.T, _, _, modern, _ string, _ []byte) {
			if err := os.Remove(filepath.Join(modern, "migration.receipt.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed receipt", mutate: func(t *testing.T, _, _, modern, _ string, _ []byte) {
			if err := os.WriteFile(filepath.Join(modern, "migration.receipt.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "archive source digest tamper", mutate: func(t *testing.T, _, _, _, archive string, _ []byte) {
			if err := os.WriteFile(filepath.Join(archive, "baseline.json"), []byte("tampered\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "destination digest tamper", mutate: func(t *testing.T, _, _, modern, _ string, receipt []byte) {
			var decoded naming.Receipt
			if err := json.Unmarshal(receipt, &decoded); err != nil {
				t.Fatal(err)
			}
			decoded.DestinationDigest = string(bytes.Repeat([]byte{'0'}, len(decoded.DestinationDigest)))
			tampered, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(modern, "migration.receipt.json"), tampered, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "project")
			legacy := filepath.Join(root, naming.LegacyProjectDir)
			modern := filepath.Join(root, naming.ProjectDir)
			writeLegacyProjectForDiscovery(t, legacy)
			plan, err := naming.PlanRoots([]naming.Root{{Kind: "project", SourceRoot: legacy, DestinationRoot: modern}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := naming.Apply(plan); err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(filepath.Join(modern, "migration.receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var decoded naming.Receipt
			if err := json.Unmarshal(receipt, &decoded); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, root, legacy, modern, decoded.Roots[0].ArchiveRoot, receipt)
			t.Setenv("HOME", parent)
			if _, _, err := FindRoot(root); err == nil {
				t.Fatal("invalid normal tombstone state was discovered")
			}
		})
	}
}

func writeLegacyProjectForDiscovery(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: migrated\nbaseline: .tplater/baseline.json\n")
	if err := os.WriteFile(filepath.Join(root, "project.yaml"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte("{\"schema\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
