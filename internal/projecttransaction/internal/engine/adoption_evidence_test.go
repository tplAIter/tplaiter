//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

func TestPlausiblePolicyCannotSubstituteUpdateReceiptForOrigin(t *testing.T) {
	tx, _, r, home := signedUpdateEngine(t)
	defer tx.Release()
	root, e := provenance.DecodeRootTemplateLock(tx.plan.Material.Before[".tplaiter/root-template.lock.json"].Data)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := adoptionpolicy.New(adoptionpolicy.Origin{ProjectID: tx.plan.Material.ProjectID, Binding: r.TrustRuntime().Binding(), SourceRootLockSHA256: root.RootLockSHA256, SourceCommit: root.Root.Commit, RendererVersion: root.Renderer.Version, RenderInputsSHA256: evidencecas.Digest(nil), DecisionAt: "2026-06-01T00:00:00Z", Exclusions: []adoptionpolicy.Exclusion{{Path: "ordinary.txt", SourceSHA256: evidencecas.Digest([]byte("signed")), SourceMode: 0o644, InitialState: "modified", Observed: adoptionpolicy.Observation{Exists: true, Mode: 0o640, Device: 1, Inode: 2, SHA256: evidencecas.Digest([]byte("ours"))}}}})
	if e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(tx.dir, "state.json")
	before, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ReadAdoptionOrigin(context.Background(), r, home, policy); e == nil {
		t.Fatal("other signed operation became adoption origin")
	}
	after, e := os.ReadFile(name)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("origin verifier mutated receipt", e)
	}
}
