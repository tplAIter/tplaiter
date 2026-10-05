package updateplan

import (
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func decisionPolicy(t *testing.T) *adoptionpolicy.Policy {
	t.Helper()
	p, e := adoptionpolicy.New(adoptionpolicy.Origin{ProjectID: "project", SourceRootLockSHA256: evidencecas.Digest([]byte("signed lock")), SourceCommit: strings.Repeat("a", 40), RendererVersion: "dev", RenderInputsSHA256: evidencecas.Digest(nil), DecisionAt: "2026-10-05T00:00:00Z", Exclusions: []adoptionpolicy.Exclusion{{Path: "nested/owned", SourceSHA256: evidencecas.Digest([]byte("signed")), SourceMode: 0o644, InitialState: "modified", Observed: adoptionpolicy.Observation{Exists: true, Mode: 0o640, Device: 1, Inode: 2, SHA256: evidencecas.Digest([]byte("ours"))}}}})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestExclusionsBypassMergeOnChangeRemovalReintroduction(t *testing.T) {
	p := decisionPolicy(t)
	for _, present := range []bool{false, true} {
		o := &observation{files: map[string][]byte{}}
		if present {
			o.files["nested/owned"] = []byte("ours")
			o.images = []Image{{Path: "nested", Kind: "directory", Mode: 0o751, SHA256: evidencecas.Digest(nil)}, {Path: "nested/owned", Kind: "file", Mode: 0o640, SHA256: evidencecas.Digest([]byte("ours"))}}
		}
		for _, variant := range []struct{ base, target map[string][]byte }{{map[string][]byte{"nested/owned": []byte("signed")}, map[string][]byte{"nested/owned": []byte("changed")}}, {map[string][]byte{"nested/owned": []byte("signed")}, map[string][]byte{}}, {map[string][]byte{}, map[string][]byte{"nested/owned": []byte("reintroduced")}}} {
			changes, e := computeChanges(o, variant.base, variant.target, p)
			if e != nil {
				t.Fatal(e)
			}
			if len(changes) != 1 || changes[0].Operation != "keep" || changes[0].Conflict || changes[0].After != changes[0].Before || len(changes[0].Content) != 0 {
				t.Fatalf("exclusion became writer %#v", changes)
			}
			plan := &Plan{policy: p, observed: o, report: Report{Changes: changes}}
			mutation, e := buildMutation(plan)
			if e != nil || len(mutation.changes) != 0 {
				t.Fatalf("mutation %v %#v", e, mutation)
			}
		}
	}
}
func TestExclusionRejectsAncestorAndCasePromotionIndependently(t *testing.T) {
	p := decisionPolicy(t)
	o := &observation{files: map[string][]byte{}}
	for _, name := range []string{"nested", "nested/owned/child", "NESTED/OWNED"} {
		if _, e := computeChanges(o, map[string][]byte{}, map[string][]byte{name: []byte("upstream")}, p); e == nil {
			t.Fatal("target topology promoted", name)
		}
		i := Image{Path: name, Kind: "file", Mode: 0o644, SHA256: evidencecas.Digest([]byte("upstream"))}
		plan := &Plan{policy: p, observed: o, report: Report{Changes: []Change{{Path: name, Operation: "write", After: &i, Content: []byte("upstream")}}}}
		if _, e := buildMutation(plan); e == nil {
			t.Fatal("mutation topology promoted", name)
		}
	}
}
func TestV1MaterialDoesNotAcquireV2PolicyFields(t *testing.T) {
	m := UpdateMaterial{Version: 1}
	a, e := updateMaterialFingerprint(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Version = 2
	b, e := updateMaterialFingerprint(m)
	if e != nil || a == b {
		t.Fatal("v1/v2 intent domains collide", e)
	}
}
