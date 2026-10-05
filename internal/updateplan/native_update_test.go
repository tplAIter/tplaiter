package updateplan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestSignedUpdateMaterialPostLeaseAndColdReconstruction(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	initial, _, err := p.TransactionMaterial(ctx, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthenticateUpdateMaterial(ctx, b.runtime, "v1", initial); err != nil {
		t.Fatal(err)
	}
	// Planner test models only the exact control observation; actual lease and
	// held-descriptor validation belong to the concrete engine adapter tests.
	lock := filepath.Join(f.project, updateControlPath)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.TransactionMaterial(ctx, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("ordinary recheck omitted control: %v", err)
	}
	leased, _, err := p.TransactionMaterialAfterLease(ctx, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if !leased.ControlAdded || leased.ExpectedFingerprint != initial.ExpectedFingerprint || leased.Before[updateControlPath].Inode == 0 {
		t.Fatal("exact control image missing")
	}
	if err := AuthenticateUpdateMaterial(ctx, b.runtime, "v1", leased); err != nil {
		t.Fatal(err)
	}
	if err := AuthenticateUpdateMaterial(ctx, b.runtime, "v2", leased); err == nil {
		t.Fatal("journal renderer version overrode actual composition renderer")
	}
	// Actual partial target image: semantic cold reconstruction must use sealed
	// BEFORE bytes, never stable-ledger verification of this incomplete tree.
	if err := os.WriteFile(filepath.Join(f.project, "hello.txt"), []byte("hello target\nstable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if err := AuthenticateUpdateMaterial(ctx, fresh, "v1", leased); err != nil {
		t.Fatalf("cold signed source/target reconstruction: %v", err)
	}
	for _, kind := range []string{"target bytes", "old source", "registry", "resource", "control"} {
		t.Run(kind, func(t *testing.T) {
			_, _, err := p.TransactionMaterial(ctx, p.Fingerprint())
			// Live plan is now stale. Detached data is used ONLY for negative semantic
			// checking, never as a constructor or a recovery grant.
			if err == nil {
				t.Fatal("partial tree accepted as stable")
			}
			m := leased
			m.Before = map[string]UpdateFile{}
			for k, v := range leased.Before {
				m.Before[k] = v
			}
			m.After = map[string]UpdateFile{}
			for k, v := range leased.After {
				m.After[k] = v
			}
			switch kind {
			case "target bytes":
				v := m.After["hello.txt"]
				v.Data = []byte("forged")
				m.After["hello.txt"] = v
			case "old source":
				m.SourceInput = in.TargetInput
			case "registry":
				m.Registry.AfterContent = []byte("forged")
			case "resource":
				v := m.After[".tplaiter/generators/generators/entity.tmpl"]
				v.Data = []byte("snippet-target\nlocal\n")
				m.After[".tplaiter/generators/generators/entity.tmpl"] = v
			case "control":
				v := m.Before[updateControlPath]
				v.Data = []byte("foreign")
				m.Before[updateControlPath] = v
			}
			m.Fingerprint, err = updateMaterialFingerprint(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := AuthenticateUpdateMaterial(ctx, fresh, "v1", m); err == nil {
				t.Fatal("self-digested transport accepted despite signed reconstruction mismatch")
			}
		})
	}
	if !bytes.Equal(leased.After[".tplaiter/generators/generators/entity.tmpl"].Data, []byte("snippet-target\nstable\n")) {
		t.Fatal("resource altered")
	}
}

func TestSignedUpdatePostLeaseForeignControlRefusal(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, updateControlPath), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.TransactionMaterialAfterLease(ctx, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("foreign control ignored: %v", err)
	}
}
