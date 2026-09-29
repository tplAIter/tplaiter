package ownership

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeWritesReservedInventoryPath(t *testing.T) {
	root := t.TempDir()
	artifact, err := ArtifactFor("app.txt", []byte("v1"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, map[string]Artifact{"app.txt": artifact}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(InventoryRelPath)))
	if err != nil {
		t.Fatalf("read initial inventory: %v", err)
	}
	var inventory Inventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("decode initial inventory: %v", err)
	}
	if len(inventory.Artifacts) != 1 {
		t.Fatalf("initial artifacts = %+v, want one", inventory.Artifacts)
	}
	got := inventory.Artifacts[0]
	if got.Path != artifact.Path || got.SHA256 != artifact.SHA256 || got.Mode != artifact.Mode || got.Target != "" || got.Kind != "" {
		t.Fatalf("initial artifact = %+v, want regular %q with digest %q", got, artifact.Path, artifact.SHA256)
	}
}

func TestInitializeWritesDeterministicEmptyInventory(t *testing.T) {
	root := t.TempDir()
	if err := Initialize(root, map[string]Artifact{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(InventoryRelPath)))
	if err != nil {
		t.Fatalf("read empty inventory: %v", err)
	}
	if got, want := string(data), "{\n  \"version\": 1\n}\n"; got != want {
		t.Fatalf("empty inventory = %q, want %q", got, want)
	}
}

func TestBuildTombstonesDeletedManagedPathUntilRestore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.txt", "v1", 0o644)
	old, err := ArtifactFor("app.txt", []byte("v1"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, map[string]Artifact{"app.txt": old}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "app.txt")); err != nil {
		t.Fatal(err)
	}

	newArtifact, err := ArtifactFor("app.txt", []byte("v2"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Build(root, Input{
		Desired:        map[string]Artifact{"app.txt": newArtifact},
		Actions:        []Action{{Path: "app.txt", Operation: Write, Content: []byte("v2"), Reason: "update"}},
		TargetBaseline: map[string]string{"app.txt": newArtifact.SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := overlay.Actions[0]; got.Operation != Keep || got.Conflict || len(got.Content) != 0 {
		t.Fatalf("tombstoned action = %+v, want keep", got)
	}
	if len(overlay.Inventory.Tombstones) != 1 || overlay.Inventory.Tombstones[0] != "app.txt" {
		t.Fatalf("tombstones = %+v", overlay.Inventory.Tombstones)
	}
	if len(overlay.Skipped) != 1 || overlay.Skipped[0] != (Decision{Path: "app.txt", Reason: "tombstone"}) {
		t.Fatalf("skipped = %+v", overlay.Skipped)
	}
	if _, ok := overlay.Baseline["app.txt"]; ok {
		t.Fatal("tombstoned absent path remained in effective baseline")
	}
	if overlay.Change == nil || overlay.Change.After == nil {
		t.Fatal("tombstone inventory change was not staged")
	}
	if _, err := os.Stat(filepath.Join(root, "app.txt")); !os.IsNotExist(err) {
		t.Fatalf("planning recreated user-deleted path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, InventoryRelPath), overlay.Change.After, 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := Build(root, Input{
		Desired:        map[string]Artifact{"app.txt": newArtifact},
		Actions:        []Action{{Path: "app.txt", Operation: Write, Content: []byte("v2"), Reason: "recreate"}},
		TargetBaseline: map[string]string{"app.txt": newArtifact.SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Actions[0].Operation != Keep || second.Change != nil {
		t.Fatalf("persistent tombstone overlay = %+v change=%+v", second.Actions[0], second.Change)
	}

	restored, err := Build(root, Input{
		Policy:         Policy{Restore: []string{"app.txt"}},
		Desired:        map[string]Artifact{"app.txt": newArtifact},
		Actions:        []Action{{Path: "app.txt", Operation: Write, Content: []byte("v2"), Reason: "recreate"}},
		TargetBaseline: map[string]string{"app.txt": newArtifact.SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if restored.Actions[0].Operation != Write || len(restored.Inventory.Tombstones) != 0 || len(restored.Inventory.Artifacts) != 1 {
		t.Fatalf("restore overlay = %+v inventory=%+v", restored.Actions[0], restored.Inventory)
	}
}

func TestBuildPolicySkipsAreDeterministicAndJSONVisible(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "local-a", 0o644)
	writeFile(t, root, "b.txt", "local-b", 0o644)
	a, err := ArtifactFor("a.txt", []byte("target-a"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ArtifactFor("b.txt", []byte("target-b"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Build(root, Input{
		Policy:  Policy{SkipIfExists: []string{"*.txt"}},
		Desired: map[string]Artifact{"a.txt": a, "b.txt": b},
		Actions: []Action{
			{Path: "b.txt", Operation: Write, Content: []byte("target-b")},
			{Path: "a.txt", Operation: Write, Content: []byte("target-a")},
		},
		TargetBaseline: map[string]string{"a.txt": a.SHA256, "b.txt": b.SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if overlay.Actions[0].Path != "a.txt" || overlay.Actions[1].Path != "b.txt" || overlay.Actions[0].Operation != Keep || overlay.Actions[1].Operation != Keep {
		t.Fatalf("canonical skipped actions = %+v", overlay.Actions)
	}
	want := []Decision{{Path: "a.txt", Reason: "skipIfExists"}, {Path: "b.txt", Reason: "skipIfExists"}}
	if len(overlay.Skipped) != len(want) {
		t.Fatalf("skipped = %+v", overlay.Skipped)
	}
	for i := range want {
		if overlay.Skipped[i] != want[i] {
			t.Fatalf("skipped[%d] = %+v, want %+v", i, overlay.Skipped[i], want[i])
		}
	}
	if overlay.Change == nil || !json.Valid(overlay.Change.After) || !bytes.Contains(overlay.Change.After, []byte(`"skipped"`)) {
		t.Fatalf("skip is not JSON-visible: %q", overlay.Change.After)
	}
	if got := overlay.Baseline["a.txt"]; got != hash([]byte("local-a")) {
		t.Fatalf("effective baseline a = %s", got)
	}
}

func TestBuildPolicySuppressionClearsWriteOnlySymlinkMetadata(t *testing.T) {
	for name, policy := range map[string]Policy{
		"exclude":        {Exclude: []string{"tool"}},
		"skip if exists": {SkipIfExists: []string{"tool"}},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "tool", "local", 0o644)
			artifact, err := ArtifactFor("tool", []byte("bin/run"), 0, "bin/run")
			if err != nil {
				t.Fatal(err)
			}
			overlay, err := Build(root, Input{
				Policy:  policy,
				Desired: map[string]Artifact{"tool": artifact},
				Actions: []Action{{
					Path: "tool", Operation: Write, Content: []byte("bin/run"),
					Mode: 0o755, SymlinkTarget: "bin/run",
				}},
				TargetBaseline: map[string]string{"tool": artifact.SHA256},
			})
			if err != nil {
				t.Fatal(err)
			}
			action := overlay.Actions[0]
			if action.Operation != Keep || action.Content != nil || action.Conflict || action.Mode != 0 || action.SymlinkTarget != "" {
				t.Fatalf("suppressed action retains write metadata: %+v", action)
			}
			// This is the invariant the update adapter relies on before it drops
			// kept actions from the transaction mutation list.
			if _, err := canonicalActions(overlay.Actions); err != nil {
				t.Fatalf("suppressed action is not canonical: %v", err)
			}
		})
	}
}

func TestBuildRejectsSymlinkedParentDuringPolicyRead(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("symlink semantics require Unix")
	}
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFor("linked/tool", []byte("target"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build(root, Input{
		Policy:         Policy{SkipIfExists: []string{"linked/**"}},
		Desired:        map[string]Artifact{"linked/tool": artifact},
		Actions:        []Action{{Path: "linked/tool", Operation: Write, Content: []byte("target")}},
		TargetBaseline: map[string]string{"linked/tool": artifact.SHA256},
	})
	if err == nil {
		t.Fatal("policy read through symlinked parent was accepted")
	}
}

func TestBuildRejectsUnsafeLegacyBasePath(t *testing.T) {
	_, err := Build(t.TempDir(), Input{BasePaths: []string{"../outside"}})
	if err == nil {
		t.Fatal("unsafe legacy base path was accepted")
	}
}

func TestReadStateAllowsSafeRelativeSymlinkAndRejectsEscape(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("symlink semantics require Unix")
	}
	root := t.TempDir()
	writeFile(t, root, "scripts/run", "#!/bin/sh\n", 0o755)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../scripts/run", filepath.Join(root, "bin", "tool")); err != nil {
		t.Fatal(err)
	}
	state, err := ReadState(root, "bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	if !state.Exists || state.Kind != KindSymlink || string(state.Data) != "../scripts/run" {
		t.Fatalf("safe symlink state = %+v", state)
	}
	if err := os.Symlink("../../outside", filepath.Join(root, "bin", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(root, "bin/escape"); err == nil {
		t.Fatal("unsafe symlink escape was accepted")
	}
}

func writeFile(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
