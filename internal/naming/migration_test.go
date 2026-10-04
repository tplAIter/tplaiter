package naming

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateEmittedSchema(t *testing.T, schemaPath string, document any) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaPath, err)
	}
	b, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
}

func writeLegacyHome(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLegacyProject(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nbaseline: .tplater/baseline.json\n")
	if err := os.WriteFile(filepath.Join(root, "project.yaml"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), []byte("{\"schema\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationPreservesBytesAndIsIdempotent(t *testing.T) {
	parent := t.TempDir()
	old, newRoot := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, old)
	if err := os.MkdirAll(filepath.Join(old, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte("legacy\x00evidence\n")
	if err := os.WriteFile(filepath.Join(old, "state", "ledger.bin"), want, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(old, newRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != nil {
		t.Fatal(err)
	}
	r, err := Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(newRoot, "state", "ledger.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("bytes changed: %q", got)
	}
	r2, err := Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if r2.PlanDigest != r.PlanDigest || r2.TransactionID != r.TransactionID {
		t.Fatalf("retry receipt differs: %#v %#v", r2, r)
	}
	if err := GuardLegacyWrite(old); !errors.Is(err, ErrLegacyWrite) {
		t.Fatalf("legacy writer guard = %v", err)
	}
	if _, err := os.Stat(legacyArchive(old, p.Digest)); err != nil {
		t.Fatalf("legacy archive missing: %v", err)
	}
}

func TestMigrationRejectsTamperedPlanAndUnsafeInputs(t *testing.T) {
	parent := t.TempDir()
	old := filepath.Join(parent, "old")
	writeLegacyHome(t, old)
	if err := os.WriteFile(filepath.Join(old, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(old, filepath.Join(parent, "new"))
	if err != nil {
		t.Fatal(err)
	}
	p.Entries[0].Bytes = []byte("tampered")
	if err := p.Verify(); err == nil {
		t.Fatal("tampered plan accepted")
	}
	p, err = PlanHome(old, filepath.Join(parent, "new2"))
	if err != nil {
		t.Fatal(err)
	}
	p.Entries[0].Path = "../escape"
	if err := p.Verify(); err == nil {
		t.Fatal("unsafe path accepted")
	}
}

func TestPlanRejectsCredentialBeforeReadAndApplyRejectsStaleTree(t *testing.T) {
	parent := t.TempDir()
	old, dst := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, old)
	if err := os.WriteFile(filepath.Join(old, "tplater.db"), []byte("must-not-read"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanHome(old, dst); err == nil {
		t.Fatal("credential capability accepted")
	}
	if err := os.Remove(filepath.Join(old, "tplater.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "safe"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(old, dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "unlisted"), []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p); err == nil {
		t.Fatal("stale plan accepted added file")
	}
}

func TestPlanRootsMigratesSupportedHome(t *testing.T) {
	parent := t.TempDir()
	src, dst := filepath.Join(parent, "home-old"), filepath.Join(parent, "home-new")
	writeLegacyHome(t, src)
	if err := os.WriteFile(filepath.Join(src, "ledger"), []byte("home"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanRoots([]Root{{Kind: "home", SourceRoot: src, DestinationRoot: dst}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Roots) != 1 {
		t.Fatalf("receipt roots = %d", len(r.Roots))
	}
	if _, err := os.Stat(filepath.Join(dst, "ledger")); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverCommitsRecordedStage(t *testing.T) {
	parent := t.TempDir()
	src, dst := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, src)
	if err := os.WriteFile(filepath.Join(src, "ledger"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.MkdirTemp(parent, "stage-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "ledger"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "state.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := receiptForPlan(p, "2000-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeCanonical(filepath.Join(stage, "migration.receipt.json"), r); err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(jp, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
		t.Fatal(err)
	}
	got, err := Recover(jp)
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanDigest != p.Digest {
		t.Fatalf("recovered %q", got.PlanDigest)
	}
	if _, err := os.Stat(filepath.Join(dst, "migration.receipt.json")); err != nil {
		t.Fatal(err)
	}
}

func writeProjectRecoveryStage(t *testing.T, p Plan, stage string) Receipt {
	t.Helper()
	root := p.Roots[0]
	entries, err := destinationEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(stage, entry.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, entry.Bytes, os.FileMode(entry.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	destinationDigest, err := digestBytes("tplaiter.dev/naming-source/v1", entries)
	if err != nil {
		t.Fatal(err)
	}
	receiptRoot := root
	receiptRoot.ArchiveRoot = legacyArchive(root.SourceRoot, p.Digest)
	receipt := Receipt{
		Schema: ReceiptSchema, Algorithm: algorithm, PlanDigest: p.Digest,
		SourceRoot: root.SourceRoot, DestinationRoot: root.DestinationRoot,
		SourceDigest: root.SourceDigest, DestinationDigest: destinationDigest,
		TransactionID: p.Digest[:16], CommittedAt: "2000-01-01T00:00:00Z",
		Roots: []Root{receiptRoot},
	}
	if err := p.writeCanonical(filepath.Join(stage, "migration.receipt.json"), receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestRecoverProjectTransformedAfterImageAndRenameWindow(t *testing.T) {
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	source := filepath.Join(projectRoot, LegacyProjectDir)
	destination := filepath.Join(projectRoot, ProjectDir)
	writeLegacyProject(t, source)
	p, err := PlanRoots([]Root{{Kind: "project", SourceRoot: source, DestinationRoot: destination}})
	if err != nil {
		t.Fatal(err)
	}
	archive := legacyArchive(source, p.Digest)
	if err := os.Rename(source, archive); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, "project-stage")
	wantReceipt := writeProjectRecoveryStage(t, p, stage)
	if err := os.Rename(stage, destination); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
		t.Fatal(err)
	}

	got, err := Recover(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanDigest != p.Digest || got.DestinationDigest != wantReceipt.DestinationDigest {
		t.Fatalf("recovered receipt = %#v, want plan %s and destination %s", got, p.Digest, wantReceipt.DestinationDigest)
	}
	marker, err := os.ReadFile(filepath.Join(destination, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(marker, []byte("baseline: .tplaiter/baseline.json")) {
		t.Fatalf("recovered marker is not transformed: %q", marker)
	}
	legacyMarker, err := os.ReadFile(filepath.Join(archive, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(legacyMarker, []byte("baseline: .tplater/baseline.json")) {
		t.Fatalf("archive marker was rewritten: %q", legacyMarker)
	}
	sealed, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(sealed, legacyTombstone) {
		t.Fatalf("legacy tombstone = %q, %v", sealed, err)
	}
	ok, err := MigratedProjectRoot(projectRoot)
	if err != nil || !ok {
		t.Fatalf("recovered project discovery = %v, %v", ok, err)
	}
	// A retry after recovery is a no-write, receipt-preserving operation.
	retry, err := Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retry, got) {
		t.Fatalf("retry receipt changed: %#v != %#v", retry, got)
	}
}

func TestRecoverRejectsTamperedProjectAfterImage(t *testing.T) {
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	source := filepath.Join(projectRoot, LegacyProjectDir)
	destination := filepath.Join(projectRoot, ProjectDir)
	writeLegacyProject(t, source)
	p, err := PlanRoots([]Root{{Kind: "project", SourceRoot: source, DestinationRoot: destination}})
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, "project-stage")
	writeProjectRecoveryStage(t, p, stage)
	if err := os.WriteFile(filepath.Join(stage, "project.yaml"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(journalPath); err == nil {
		t.Fatal("tampered transformed after-image was recovered")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("tampered recovery created destination: %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source changed after rejected recovery: %v", err)
	}
}

func TestPlanRejectsOverlappingAndAdditionalCredentialRoots(t *testing.T) {
	parent := t.TempDir()
	src := filepath.Join(parent, "source")
	writeLegacyHome(t, src)
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "auth.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanHome(src, filepath.Join(parent, "dst")); err == nil {
		t.Fatal("auth capability accepted")
	}
	if err := os.Remove(filepath.Join(src, "auth.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRoots([]Root{{Kind: "home", SourceRoot: src, DestinationRoot: filepath.Join(parent, "one")}, {Kind: "registry", SourceRoot: filepath.Join(src, "nested"), DestinationRoot: filepath.Join(parent, "two")}}); err == nil {
		t.Fatal("overlapping roots accepted")
	}
}

func TestPlanRejectsUnsupportedFormatsBeforeWrites(t *testing.T) {
	parent := t.TempDir()
	for _, kind := range []string{"project", "registry", "cas"} {
		src := filepath.Join(parent, kind)
		if err := os.MkdirAll(src, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "ledger"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := PlanRoots([]Root{{Kind: kind, SourceRoot: src, DestinationRoot: filepath.Join(parent, kind+"-new")}}); err == nil {
			t.Fatalf("%s accepted without an adapter", kind)
		}
	}
}

func TestHomeWithTypedLegacyProjectsRegistryIsCaptured(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	writeLegacyHome(t, home)
	if err := os.WriteFile(filepath.Join(home, "projects.yaml"), []byte("version: 1\nitems: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(home, filepath.Join(parent, "new"))
	if err != nil {
		t.Fatalf("typed registry rejected: %v", err)
	}
	if err := p.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryRelocationPreservesOfflineRecordsAndArchive(t *testing.T) {
	parent := t.TempDir()
	oldHome, newHome := filepath.Join(parent, "old-home"), filepath.Join(parent, "new-home")
	writeLegacyHome(t, oldHome)
	if err := os.WriteFile(filepath.Join(oldHome, "config.yaml"), []byte("version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath, newPath := filepath.Join(parent, "old-place"), filepath.Join(parent, "moved-place")
	registry := []byte("version: 1\nitems:\n  - id: moved-id\n    path: " + newPath + "\n    template: {repo: demo, name: api, version: v1}\n    createdAt: 2020-01-01T00:00:00Z\n    lastSeenAt: 2021-01-01T00:00:00Z\n    baselineSHA: abc\n  - id: offline-id\n    path: /unavailable/offline\n    template: {repo: demo, name: offline, version: v2}\n    createdAt: 2022-01-01T00:00:00Z\n    lastSeenAt: 2023-01-01T00:00:00Z\n    baselineSHA: def\n")
	// The authoritative legacy registry still points to the pre-move path;
	// constructing it separately keeps the test readable while newPath hosts
	// the actual marker that proves the move.
	registry = bytes.Replace(registry, []byte("path: "+newPath), []byte("path: "+oldPath), 1)
	if err := os.WriteFile(filepath.Join(oldHome, "projects.yaml"), registry, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyMarker := filepath.Join(newPath, LegacyProjectDir)
	writeLegacyProject(t, legacyMarker)
	markerPath := filepath.Join(legacyMarker, "project.yaml")
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	marker = bytes.Replace(marker, []byte("kind: Project\n"), []byte("kind: Project\nid: moved-id\n"), 1)
	if err := os.WriteFile(markerPath, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanRoots([]Root{
		{Kind: "home", SourceRoot: oldHome, DestinationRoot: newHome, Relocations: []Relocation{{ID: "moved-id", OldPath: oldPath, NewPath: newPath}}},
		{Kind: "project", SourceRoot: legacyMarker, DestinationRoot: filepath.Join(newPath, ProjectDir)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != nil {
		t.Fatal(err)
	}
	if p.Roots[0].Relocations[0].ProjectMarkerDigest == "" {
		t.Fatal("planner did not bind marker preimage")
	}
	forged := p
	forged.Roots = append([]Root(nil), p.Roots...)
	forged.Roots[0].Relocations = append([]Relocation(nil), p.Roots[0].Relocations...)
	forged.Roots[0].Relocations[0].OldPath = filepath.Join(parent, "forged-old")
	forged, err = forged.seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Verify(); err == nil {
		t.Fatal("re-sealed forged relocation was accepted")
	}
	forged = p
	forged.Roots = append([]Root(nil), p.Roots...)
	forged.Roots[0].Relocations = append([]Relocation(nil), p.Roots[0].Relocations...)
	forged.Roots[0].Relocations[0].OldPath += "/"
	forged, err = forged.seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := forged.Verify(); err == nil {
		t.Fatal("non-canonical relocation path was accepted")
	}
	validateEmittedSchema(t, "../../schema/naming-migration-plan.v1.schema.json", p)
	receipt, err := Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	validateEmittedSchema(t, "../../schema/naming-migration-receipt.v1.schema.json", receipt)
	if ok, err := MigratedProjectRoot(newPath); err != nil || !ok {
		t.Fatalf("multi-root project receipt not discoverable: %v, %v", ok, err)
	}
	got, err := os.ReadFile(filepath.Join(newHome, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	projects, err := decodeLegacyProjects(got)
	if err != nil {
		t.Fatal(err)
	}
	if projects.Items[0].Path != newPath || projects.Items[0].CreatedAt.Format(time.RFC3339) != "2020-01-01T00:00:00Z" || projects.Items[1].Path != "/unavailable/offline" || projects.Items[1].Template.Name != "offline" {
		t.Fatalf("registry after-image lost identity/history: %#v", projects.Items)
	}
	archived, err := os.ReadFile(filepath.Join(legacyArchive(oldHome, p.Digest), "projects.yaml"))
	if err != nil || !bytes.Equal(archived, registry) {
		t.Fatalf("registry archive changed: %v", err)
	}
	if _, err := Apply(p); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
}

func TestRegistryRelocationRejectsForgedOrUnpairedEvidence(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	writeLegacyHome(t, home)
	if err := os.WriteFile(filepath.Join(home, "projects.yaml"), []byte("version: 1\nitems:\n- id: one\n  path: /old\n  template: {repo: r, name: n, version: v}\n  createdAt: 2020-01-01T00:00:00Z\n  lastSeenAt: 2020-01-01T00:00:00Z\n  baselineSHA: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRoots([]Root{{Kind: "home", SourceRoot: home, DestinationRoot: filepath.Join(parent, "new"), Relocations: []Relocation{{ID: "one", OldPath: "/old", NewPath: "/new"}}}}); err == nil {
		t.Fatal("unpaired relocation accepted")
	}
}

func TestApplyRejectsUnboundSameDigestReceiptWithoutSourceWrite(t *testing.T) {
	parent := t.TempDir()
	source, destination := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, source)
	p, err := PlanHome(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "migration.receipt.json"), []byte(`{"planDigest":"`+p.Digest+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p); err == nil {
		t.Fatal("unbound same-digest receipt accepted")
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source changed: %v", err)
	}
}

func TestRecoverRejectsUnboundSameDigestReceiptWithoutSourceWrite(t *testing.T) {
	parent := t.TempDir()
	source, destination := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, source)
	p, err := PlanHome(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, "stage")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "migration.receipt.json"), []byte(`{"planDigest":"`+p.Digest+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(journalPath); err == nil {
		t.Fatal("recovery accepted unbound same-digest receipt")
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source changed: %v", err)
	}
}

func writeRecoveryStage(t *testing.T, p Plan, root Root, stage string) {
	t.Helper()
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := destinationEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(stage, entry.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, entry.Bytes, os.FileMode(entry.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := receiptForPlan(p, "2000-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeCanonical(filepath.Join(stage, "migration.receipt.json"), r); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptRejectsMultiRootProjectionAndRootTamper(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*Receipt)
	}{
		{"top-level projection", func(r *Receipt) { r.DestinationRoot = r.Roots[1].DestinationRoot }},
		{"ordered roots", func(r *Receipt) { r.Roots[0], r.Roots[1] = r.Roots[1], r.Roots[0] }},
		{"cross-root digest", func(r *Receipt) { r.Roots[0].DestinationDigest = r.Roots[1].DestinationDigest }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			parent := t.TempDir()
			home := filepath.Join(parent, "home")
			project := filepath.Join(parent, "project", LegacyProjectDir)
			writeLegacyHome(t, home)
			writeLegacyProject(t, project)
			p, err := PlanRoots([]Root{{Kind: "home", SourceRoot: home, DestinationRoot: filepath.Join(parent, "new-home")}, {Kind: "project", SourceRoot: project, DestinationRoot: filepath.Join(parent, "project", ProjectDir)}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(p); err != nil {
				t.Fatal(err)
			}
			roots := migrationOrder(p.Roots)
			b, err := os.ReadFile(filepath.Join(roots[0].DestinationRoot, "migration.receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var r Receipt
			if err := json.Unmarshal(b, &r); err != nil {
				t.Fatal(err)
			}
			mutate.fn(&r)
			b, err = json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, root := range roots {
				if err := os.WriteFile(filepath.Join(root.DestinationRoot, "migration.receipt.json"), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, ok := matchingReceipt(roots[0], p); ok {
				t.Fatal("tampered multi-root receipt matched")
			}
			if ok, err := MigratedProjectRoot(filepath.Join(parent, "project")); err != nil || ok {
				t.Fatalf("tampered receipt discovered: %v, %v", ok, err)
			}
		})
	}
}

func TestRecoverPreflightsReceiptAndSourceBeforeSealing(t *testing.T) {
	makePlan := func(t *testing.T) (Plan, []Root, string) {
		parent := t.TempDir()
		source := filepath.Join(parent, "old")
		writeLegacyHome(t, source)
		p, err := PlanHome(source, filepath.Join(parent, "new"))
		if err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(parent, "stage")
		writeRecoveryStage(t, p, p.Roots[0], stage)
		journalPath := filepath.Join(parent, "journal.json")
		if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
			t.Fatal(err)
		}
		return p, p.Roots, journalPath
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, p Plan, roots []Root, journal string)
	}{
		{"top-level stage projection tamper", func(t *testing.T, _ Plan, _ []Root, journal string) {
			path := filepath.Join(filepath.Dir(journal), "stage", "migration.receipt.json")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var r Receipt
			if err := json.Unmarshal(b, &r); err != nil {
				t.Fatal(err)
			}
			r.DestinationDigest = strings.Repeat("0", len(r.DestinationDigest))
			b, err = json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed stage receipt", func(t *testing.T, _ Plan, _ []Root, journal string) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(journal), "stage", "migration.receipt.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink stage receipt", func(t *testing.T, _ Plan, _ []Root, journal string) {
			path := filepath.Join(filepath.Dir(journal), "stage", "migration.receipt.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(journal), "outside"), path); err != nil {
				t.Fatal(err)
			}
		}},
		{"stale source", func(t *testing.T, _ Plan, roots []Root, _ string) {
			if err := os.WriteFile(filepath.Join(roots[0].SourceRoot, "state.yaml"), []byte("version: 2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed source beside archive", func(t *testing.T, p Plan, roots []Root, _ string) {
			archive := legacyArchive(roots[0].SourceRoot, p.Digest)
			if err := os.Rename(roots[0].SourceRoot, archive); err != nil {
				t.Fatal(err)
			}
			writeLegacyHome(t, roots[0].SourceRoot)
			if err := os.WriteFile(filepath.Join(roots[0].SourceRoot, "state.yaml"), []byte("version: 2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, roots, journal := makePlan(t)
			tc.mutate(t, p, roots, journal)
			if _, err := Recover(journal); err == nil {
				t.Fatal("unsafe recovery succeeded")
			}
			if _, err := os.Lstat(roots[0].DestinationRoot); !os.IsNotExist(err) {
				t.Fatalf("recovery wrote destination: %v", err)
			}
			info, err := os.Lstat(roots[0].SourceRoot)
			if err != nil || !info.IsDir() {
				t.Fatalf("recovery sealed source: %v", err)
			}
		})
	}
}

func TestRecoverSealsValidDestinationBeforeArchiveWindow(t *testing.T) {
	parent := t.TempDir()
	source, destination := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, source)
	p, err := PlanHome(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, "stage")
	writeRecoveryStage(t, p, p.Roots[0], stage)
	journalPath := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: []string{stage}}); err != nil {
		t.Fatal(err)
	}
	// Model the durable window after stage->destination but before source->archive.
	if err := os.Rename(stage, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(journalPath); err != nil {
		t.Fatalf("recover destination-before-archive: %v", err)
	}
	if err := GuardLegacyWrite(source); !errors.Is(err, ErrLegacyWrite) {
		t.Fatalf("source not sealed: %v", err)
	}
	if _, err := os.Stat(legacyArchive(source, p.Digest)); err != nil {
		t.Fatalf("archive missing: %v", err)
	}
}

func TestReceiptDecoderRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, body := range []string{
		`{"schema":"` + ReceiptSchema + `","schema":"other"}`,
		`{"unknown":true}`,
	} {
		path := filepath.Join(t.TempDir(), "migration.receipt.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readReceipt(path); err == nil {
			t.Fatalf("accepted non-strict receipt %s", body)
		}
	}
}

func TestRecoverRegistryRelocationPreservesArchiveAndOfflineRecord(t *testing.T) {
	parent := t.TempDir()
	oldHome, newHome := filepath.Join(parent, "old-home"), filepath.Join(parent, "new-home")
	writeLegacyHome(t, oldHome)
	oldPath, newPath := filepath.Join(parent, "old"), filepath.Join(parent, "moved")
	registry := []byte("version: 1\nitems:\n- id: move\n  path: " + oldPath + "\n  template: {repo: r, name: n, version: v}\n  createdAt: 2020-01-01T00:00:00Z\n  lastSeenAt: 2020-01-01T00:00:00Z\n  baselineSHA: a\n- id: offline\n  path: /offline\n  template: {repo: r, name: offline, version: v}\n  createdAt: 2020-01-01T00:00:00Z\n  lastSeenAt: 2020-01-01T00:00:00Z\n  baselineSHA: b\n")
	if err := os.WriteFile(filepath.Join(oldHome, "projects.yaml"), registry, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(newPath, LegacyProjectDir)
	writeLegacyProject(t, legacy)
	markerPath := filepath.Join(legacy, "project.yaml")
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, bytes.Replace(marker, []byte("kind: Project\n"), []byte("kind: Project\nid: move\n"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := PlanRoots([]Root{{Kind: "home", SourceRoot: oldHome, DestinationRoot: newHome, Relocations: []Relocation{{ID: "move", OldPath: oldPath, NewPath: newPath}}}, {Kind: "project", SourceRoot: legacy, DestinationRoot: filepath.Join(newPath, ProjectDir)}})
	if err != nil {
		t.Fatal(err)
	}
	roots := migrationOrder(p.Roots)
	stages := make([]string, len(roots))
	receiptRoots := append([]Root(nil), roots...)
	for i := range receiptRoots {
		receiptRoots[i].ArchiveRoot = legacyArchive(receiptRoots[i].SourceRoot, p.Digest)
	}
	first, err := destinationEntries(roots[0])
	if err != nil {
		t.Fatal(err)
	}
	destinationDigest, err := digestBytes("tplaiter.dev/naming-source/v1", first)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{Schema: ReceiptSchema, Algorithm: algorithm, PlanDigest: p.Digest, SourceRoot: roots[0].SourceRoot, DestinationRoot: roots[0].DestinationRoot, SourceDigest: roots[0].SourceDigest, DestinationDigest: destinationDigest, TransactionID: p.Digest[:16], CommittedAt: "2000-01-01T00:00:00Z", Roots: receiptRoots}
	for i, root := range roots {
		stages[i] = filepath.Join(parent, "stage-"+root.Kind)
		if err := os.MkdirAll(stages[i], 0o700); err != nil {
			t.Fatal(err)
		}
		entries, err := destinationEntries(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			path := filepath.Join(stages[i], entry.Path)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, entry.Bytes, os.FileMode(entry.Mode)); err != nil {
				t.Fatal(err)
			}
		}
		if err := p.writeCanonical(filepath.Join(stages[i], "migration.receipt.json"), receipt); err != nil {
			t.Fatal(err)
		}
	}
	journalPath := filepath.Join(parent, "journal.json")
	if err := p.writeCanonical(journalPath, journal{Plan: p, Phase: "committing", Stages: stages}); err != nil {
		t.Fatal(err)
	}
	// Model a crash after the home destination/archive/tombstone commit, with
	// the paired project stage still pending. A fresh Apply must refuse this
	// state; only the recorded journal may finish it.
	if err := os.Rename(stages[0], newHome); err != nil {
		t.Fatal(err)
	}
	if err := sealLegacyRoot(oldHome, p.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p); err == nil {
		t.Fatal("fresh apply continued partial transaction")
	}
	if _, err := Recover(journalPath); err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(filepath.Join(legacyArchive(oldHome, p.Digest), "projects.yaml"))
	if err != nil || !bytes.Equal(archived, registry) {
		t.Fatalf("archive differs: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(newHome, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	projects, err := decodeLegacyProjects(got)
	if err != nil {
		t.Fatal(err)
	}
	if projects.Items[0].Path != newPath || projects.Items[1].Path != "/offline" || projects.Items[1].ID != "offline" {
		t.Fatalf("recovery registry mismatch: %#v", projects.Items)
	}
}

func TestProjectMigrationPreservesLedgerAndMakesReceiptDiscoverable(t *testing.T) {
	parent := t.TempDir()
	projectRoot := filepath.Join(parent, "project")
	legacy := filepath.Join(projectRoot, ".tplater")
	modern := filepath.Join(projectRoot, ".tplaiter")
	writeLegacyProject(t, legacy)
	before, err := os.ReadFile(filepath.Join(legacy, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanRoots([]Root{{Kind: "project", SourceRoot: legacy, DestinationRoot: modern}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p); err != nil {
		t.Fatal(err)
	}
	if ok, err := MigratedProjectRoot(projectRoot); err != nil || !ok {
		t.Fatalf("migrated project recognized = %v, %v", ok, err)
	}
	got, err := os.ReadFile(filepath.Join(legacyArchive(legacy, p.Digest), "baseline.json"))
	if err != nil || string(got) != string(before) {
		t.Fatalf("legacy baseline changed: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(modern, "project.yaml")); err != nil {
		t.Fatalf("modern marker missing: %v", err)
	}
	modernMarker, err := os.ReadFile(filepath.Join(modern, "project.yaml"))
	if err != nil || !bytes.Contains(modernMarker, []byte("baseline: .tplaiter/baseline.json")) {
		t.Fatalf("modern marker did not point at new baseline: %q, %v", modernMarker, err)
	}
	legacyMarker, err := os.ReadFile(filepath.Join(legacyArchive(legacy, p.Digest), "project.yaml"))
	if err != nil || !bytes.Contains(legacyMarker, []byte("baseline: .tplater/baseline.json")) {
		t.Fatalf("legacy marker bytes were not preserved: %q, %v", legacyMarker, err)
	}
	if _, err := PlanRoots([]Root{{Kind: "project", SourceRoot: projectRoot, DestinationRoot: modern}}); err == nil {
		t.Fatal("project root, rather than marker root, was accepted")
	}
}

func TestProjectMigrationAndActiveNewTransactionFailClosed(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	writeLegacyHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, "transactions", "new", "tx-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "transactions", "new", "tx-1", "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanHome(home, filepath.Join(parent, "new-home")); err == nil {
		t.Fatal("active new transaction accepted")
	}
}

func TestProjectPlanVerifyAndApplyRejectForgedRootPair(t *testing.T) {
	parent := t.TempDir()
	legacy := filepath.Join(parent, "project", ".tplater")
	writeLegacyProject(t, legacy)
	p, err := PlanRoots([]Root{{Kind: "project", SourceRoot: legacy, DestinationRoot: filepath.Join(parent, "project", ".tplaiter")}})
	if err != nil {
		t.Fatal(err)
	}
	// Re-sealing proves this is not merely a stale-digest rejection: Verify and
	// Apply must enforce the authority boundary themselves.
	p.Roots[0].DestinationRoot = filepath.Join(parent, "elsewhere", ".tplaiter")
	p.DestinationRoot = p.Roots[0].DestinationRoot
	p, err = p.seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err == nil {
		t.Fatal("forged project root pair verified")
	}
	if _, err := Apply(p); err == nil {
		t.Fatal("forged project root pair applied")
	}
	if _, err := os.Stat(filepath.Join(parent, "elsewhere")); !os.IsNotExist(err) {
		t.Fatalf("forged apply wrote destination: %v", err)
	}
}

func TestSealLegacyRootRecoversRenameBeforeTombstone(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "legacy")
	writeLegacyHome(t, source)
	p, err := PlanHome(source, filepath.Join(parent, "modern"))
	if err != nil {
		t.Fatal(err)
	}
	archive := legacyArchive(source, p.Digest)
	if err := os.Rename(source, archive); err != nil {
		t.Fatal(err)
	}
	if err := sealLegacyRoot(source, p.Digest); err != nil {
		t.Fatalf("recovery from rename window: %v", err)
	}
	if err := GuardLegacyWrite(source); !errors.Is(err, ErrLegacyWrite) {
		t.Fatalf("recovered source guard = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(archive, "state.yaml")); err != nil || string(got) != "version: 1\n" {
		t.Fatalf("archive changed during recovery: %q, %v", got, err)
	}
}

func TestLegacyFormatRejectsCommentsAndUnknownFields(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state.yaml"), []byte("note: version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanHome(home, filepath.Join(parent, "modern")); err == nil {
		t.Fatal("comment spoof accepted as legacy state")
	}
	if err := os.WriteFile(filepath.Join(home, "state.yaml"), []byte("version: 1\nunknown: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanHome(home, filepath.Join(parent, "modern")); err == nil {
		t.Fatal("unknown legacy state field accepted")
	}
}

func TestPlanRejectsUnknownLegacyStateMajorBeforeWrites(t *testing.T) {
	for _, version := range []string{"2", "999"} {
		t.Run("version-"+version, func(t *testing.T) {
			parent := t.TempDir()
			source := filepath.Join(parent, "legacy")
			destination := filepath.Join(parent, "modern")
			state := []byte("version: " + version + "\n")
			if err := os.MkdirAll(source, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "state.yaml"), state, 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := PlanHome(source, destination); err == nil {
				t.Fatalf("unknown legacy state major %s accepted", version)
			}
			if got, err := os.ReadFile(filepath.Join(source, "state.yaml")); err != nil || !bytes.Equal(got, state) {
				t.Fatalf("unknown-major plan changed source: %q, %v", got, err)
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatalf("unknown-major plan created destination: %v", err)
			}
		})
	}
}

// TestActiveTransactionUsesLedgerClassification pins migrate-state to the
// shared state-ledger probe list: durable journals and pending markers block
// planning, while persistent advisory lock files do not prove an active
// transaction.
func TestActiveTransactionUsesLedgerClassification(t *testing.T) {
	for _, rel := range []string{"update/active.json", "new-transaction.pending", "transactions/new/tx-1/active.json"} {
		root := t.TempDir()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := activeTransaction(root); err == nil || !strings.Contains(err.Error(), filepath.FromSlash(rel)) {
			t.Fatalf("%s: activeTransaction=%v", rel, err)
		}
	}
	for _, rel := range []string{".lock", "update.lock", "transactions/new.lock"} {
		root := t.TempDir()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := activeTransaction(root); err != nil {
			t.Fatalf("%s: persistent lock blocked migration: %v", rel, err)
		}
	}
	if err := activeTransaction(t.TempDir()); err != nil {
		t.Fatalf("clean root refused: %v", err)
	}
}

func TestHomeWriterLockHolder(t *testing.T) {
	root := os.Getenv("TPLAITER_NAMING_LOCK_HOLDER")
	if root == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		t.Fatal(err)
	}
	var release [1]byte
	_, _ = os.Stdin.Read(release[:])
}

func TestHomeMigrationCoordinatesWriterLock(t *testing.T) {
	parent := t.TempDir()
	source, target := filepath.Join(parent, "old"), filepath.Join(parent, "new")
	writeLegacyHome(t, source)
	if err := os.WriteFile(filepath.Join(source, ".lock"), []byte("persistent lock bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHomeWriterLockHolder$")
	cmd.Env = append(os.Environ(), "TPLAITER_NAMING_LOCK_HOLDER="+source)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lock holder readiness %q: %v %s", line, err, stderr.String())
	}
	before, err := capture(source)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanHome(source, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p); err == nil || !strings.Contains(err.Error(), "home writer lock unavailable") {
		t.Fatalf("migration while writer holds lock: %v", err)
	}
	after, err := capture(source)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("busy migration changed source: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("busy migration created destination: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("lock holder: %v %s", err, stderr.String())
	}
	if _, err := Apply(p); err != nil {
		t.Fatalf("inactive persistent lock blocked migration: %v", err)
	}
	for _, root := range []string{target, legacyArchive(source, p.Digest)} {
		if b, err := os.ReadFile(filepath.Join(root, ".lock")); err != nil || string(b) != "persistent lock bytes\n" {
			t.Fatalf("persistent lock bytes not preserved at %s: %q %v", root, b, err)
		}
	}
}
