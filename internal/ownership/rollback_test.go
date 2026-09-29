package ownership

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// treeImage records every path under root with its kind, mode and bytes (or
// link target). It is the evidence used to prove that planning is read-only
// and that a Change.Before image rolls the ledger back exactly.
func treeImage(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().String()
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			line += " -> " + target
		case info.Mode().IsRegular():
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			line += " " + hash(b)
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}

func TestBuildNeverMutatesAndBeforeImageRollsBackExactly(t *testing.T) {
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
	link, err := ArtifactFor("bin/tool", []byte("../scripts/run"), 0, "../scripts/run")
	if err != nil {
		t.Fatal(err)
	}
	script, err := ArtifactFor("scripts/run", []byte("#!/bin/sh\n"), 0o755, "")
	if err != nil {
		t.Fatal(err)
	}
	if script.Mode != 0o755 || link.Kind != KindSymlink || link.Target != "../scripts/run" {
		t.Fatalf("metadata lost: script=%+v link=%+v", script, link)
	}
	if err := Initialize(root, map[string]Artifact{"bin/tool": link, "scripts/run": script}); err != nil {
		t.Fatal(err)
	}
	before := treeImage(t, root)
	// Upstream retargets the link and the user removed nothing: a pure plan.
	retarget, err := ArtifactFor("bin/tool", []byte("../scripts/run2"), 0, "../scripts/run2")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Build(root, Input{
		Policy:         Policy{SkipIfExists: []string{"scripts/**"}},
		Desired:        map[string]Artifact{"bin/tool": retarget, "scripts/run": script},
		Actions:        []Action{{Path: "bin/tool", Operation: Write, Content: []byte("../scripts/run2"), SymlinkTarget: "../scripts/run2"}, {Path: "scripts/run", Operation: Write, Content: []byte("#!/bin/sh\n"), Mode: 0o755}},
		TargetBaseline: map[string]string{"bin/tool": retarget.SHA256, "scripts/run": script.SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := treeImage(t, root); got != before {
		t.Fatalf("Build mutated the project:\nbefore=%s\nafter=%s", before, got)
	}
	if overlay.Change == nil || overlay.Change.Before == nil || overlay.Change.After == nil {
		t.Fatalf("ledger change not staged: %+v", overlay.Change)
	}
	// Simulate the transactional apply of the ledger image, then a rollback.
	inventory := filepath.Join(root, filepath.FromSlash(InventoryRelPath))
	if err := os.WriteFile(inventory, overlay.Change.After, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventory, overlay.Change.Before, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := treeImage(t, root); got != before {
		t.Fatalf("rollback image differs:\nbefore=%s\nafter=%s", before, got)
	}
	skipped := overlay.Skipped
	if len(skipped) != 1 || skipped[0] != (Decision{Path: "scripts/run", Reason: "skipIfExists"}) {
		t.Fatalf("skip decisions=%+v", skipped)
	}
}

func TestExcludedUpstreamDeletionKeepsOwnedArtifact(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "config.yaml", "local", 0o644)
	owned, err := ArtifactFor("config.yaml", []byte("v1"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, map[string]Artifact{"config.yaml": owned}); err != nil {
		t.Fatal(err)
	}
	overlay, err := Build(root, Input{
		Policy:  Policy{Exclude: []string{"config.yaml"}},
		Desired: map[string]Artifact{},
		Actions: []Action{{Path: "config.yaml", Operation: Delete}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if overlay.Actions[0].Operation != Keep {
		t.Fatalf("excluded delete was not suppressed: %+v", overlay.Actions[0])
	}
	if len(overlay.Inventory.Artifacts) != 1 || overlay.Inventory.Artifacts[0].Path != "config.yaml" {
		t.Fatalf("excluded artifact dropped: %+v", overlay.Inventory.Artifacts)
	}
	if got := overlay.Baseline["config.yaml"]; got != hash([]byte("local")) {
		t.Fatalf("baseline follows the user copy: %s", got)
	}
}

func TestInitializeRefusesToOverwriteLedger(t *testing.T) {
	root := t.TempDir()
	if err := Initialize(root, map[string]Artifact{}); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, map[string]Artifact{}); err == nil {
		t.Fatal("existing ownership ledger was overwritten")
	}
}

func TestReservedAndUnsafePathsAreRejected(t *testing.T) {
	for _, rel := range []string{InventoryRelPath, ".tplaiter/update/active.json", "../escape", "/abs", "a/../b", `a\b`} {
		if _, err := ArtifactFor(rel, []byte("x"), 0o644, ""); err == nil {
			t.Errorf("ArtifactFor(%q) accepted", rel)
		}
	}
	for _, target := range []string{"/etc/passwd", "../../outside", ""} {
		if err := ValidateRelativeSymlink("bin/tool", target); err == nil {
			t.Errorf("symlink target %q accepted", target)
		}
	}
}

func TestEmittedInventoryMatchesSchema(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "local", 0o644)
	a, err := ArtifactFor("a.txt", []byte("target"), 0o640, "")
	if err != nil {
		t.Fatal(err)
	}
	link, err := ArtifactFor("l", []byte("a.txt"), 0, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Build(root, Input{
		Policy:         Policy{SkipIfExists: []string{"a.txt"}},
		BasePaths:      []string{"gone.txt"},
		Desired:        map[string]Artifact{"a.txt": a, "l": link},
		Actions:        []Action{{Path: "a.txt", Operation: Write, Content: []byte("target")}, {Path: "l", Operation: Write, Content: []byte("a.txt"), SymlinkTarget: "a.txt"}},
		TargetBaseline: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "ownership.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(overlay.Change.After))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("emitted inventory rejected: %v\n%s", err, overlay.Change.After)
	}
	var decoded Inventory
	if err := json.Unmarshal(overlay.Change.After, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Tombstones) != 1 || decoded.Tombstones[0] != "gone.txt" || len(decoded.Skipped) != 1 {
		t.Fatalf("decoded=%+v", decoded)
	}
}
