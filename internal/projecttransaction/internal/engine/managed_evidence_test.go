//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestCommittedUpdateMaterialReadOnly(t *testing.T) {
	ctx := context.Background()
	tx, f, r, home := signedUpdateEngine(t)
	defer tx.Release()
	if _, err := ReadCommittedUpdate(ctx, r, home, tx.ID()); err == nil {
		t.Fatal("active receipt accepted")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := inspectionMetadata(t, tx.plan.Material.Root, home, r.ScratchRoot())
	if _, err := ReadCommittedUpdate(ctx, r, home, tx.ID()); err == nil {
		t.Fatal("missing exact source CAS accepted")
	}
	assertInspectionUnchanged(t, before, tx.plan.Material.Root, home, r.ScratchRoot())
	// Copy only the fixture's authenticated public source blobs into its actual
	// configured lifecycle CAS. The production reader has no bootstrap fallback.
	store, err := trustload.OpenReadOnly(ctx, f.selection)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := inspectionReferences(tx.plan.Material)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		raw, err := store.Read(ctx, ref)
		if err != nil || evidencecas.Digest(raw) != ref {
			t.Fatal("signed fixture CAS", err)
		}
		leaf := strings.TrimPrefix(ref, "sha256:")
		name := filepath.Join(f.evidence, "sha256", leaf[:2], leaf[2:])
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before = inspectionMetadata(t, tx.plan.Material.Root, home, r.ScratchRoot())
	receipt, err := ReadCommittedUpdate(ctx, r, home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	material, err := receipt.MaterialFor(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := canonicaljson.Canonical(tx.plan.Material)
	got, _ := canonicaljson.Canonical(material)
	if !bytes.Equal(want, got) {
		t.Fatal("committed material differs")
	}
	material.After["injected"] = File{Data: Bytes{1}, Mode: 0o644}
	detached, err := receipt.MaterialFor(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := detached.After["injected"]; ok {
		t.Fatal("caller mutation changed retained material")
	}
	if _, err := receipt.MaterialFor(ctx, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatal("foreign runtime accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := receipt.MaterialFor(canceled, r); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation", err)
	}
	assertInspectionUnchanged(t, before, tx.plan.Material.Root, home, r.ScratchRoot())
	stateName := filepath.Join(tx.dir, "state.json")
	raw, err := os.ReadFile(stateName)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateName, append(raw, byte('x')), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.MaterialFor(ctx, r); err == nil {
		t.Fatal("tampered terminal receipt accepted")
	}
	if err := os.WriteFile(stateName, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.MaterialFor(ctx, r); err != nil {
		t.Fatal("restored exact terminal receipt", err)
	}
	missing := filepath.Join(f.dir, "absent-home")
	if _, err := ReadCommittedUpdate(ctx, r, missing, tx.ID()); err == nil {
		t.Fatal("absent home accepted")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("read created missing home", err)
	}
}
