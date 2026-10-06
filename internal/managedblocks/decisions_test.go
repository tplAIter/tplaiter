package managedblocks

import (
	"bytes"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

func TestManagedDecisionsSignedDeleteAndRename(t *testing.T) {
	base := []byte("package p\n// tplater:managed-begin id=old provider=root\nfunc f() {}\n// tplater:managed-end id=old\n")
	ours := bytes.Replace(base, []byte("func f() {}"), []byte("func f() { println(1) }"), 1)
	baseline, err := SignedRootBaseline(map[string][]byte{"x.go": base}, baselineSource())
	if err != nil {
		t.Fatal(err)
	}
	d := evidencecas.Digest([]byte("lock"))
	v := Decision{Action: "keep", Path: "x.go", Provider: "root", OldID: "old", SourceRootLockSHA256: d, TargetRootLockSHA256: d, BaselineBodySHA256: baseline.Files["x.go"].Blocks["old"].BodySHA256, ObservedFileSHA256: evidencecas.Digest(ours)}
	wire := Decisions{APIVersion: DecisionsAPIVersion, Decisions: []Decision{v}}
	raw, _ := canonicaljson.Canonical(wire)
	parsed, err := ParseDecisions(raw)
	if err != nil {
		t.Fatal(err)
	}
	deleted := []byte("package p\n")
	res, renames, err := FileDecisions(parsed, "x.go", d, d, baseline.Files["x.go"], ours, deleted, nil)
	if err != nil || res["old"] != DeleteKeep || len(renames) != 0 {
		t.Fatal(err)
	}
	if _, _, err := FileDecisions(parsed, "x.go", d, d, baseline.Files["x.go"], base, deleted, nil); err == nil {
		t.Fatal("stale observed file accepted")
	}
	target := bytes.ReplaceAll(base, []byte("id=old"), []byte("id=next"))
	doc, _ := Parse("x.go", target)
	v.Action = "rename"
	v.NewID = "next"
	v.TargetBodySHA256 = evidencecas.Digest(doc.ByID["next"].Body)
	wire.Decisions = []Decision{v}
	raw, _ = canonicaljson.Canonical(wire)
	parsed, err = ParseDecisions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := FileDecisions(parsed, "x.go", d, d, baseline.Files["x.go"], ours, target, nil); err == nil {
		t.Fatal("unsigned replacement accepted")
	}
	signed := &manifest.ManagedBlocks{Version: 1, Replacements: []manifest.ManagedReplacement{{Path: "x.go", Provider: "root", OldID: "old", NewID: "next"}}}
	_, renames, err = FileDecisions(parsed, "x.go", d, d, baseline.Files["x.go"], ours, target, signed)
	if err != nil || renames["next"] != "old" {
		t.Fatal(err)
	}
	wire.Decisions = append(wire.Decisions, v)
	raw, _ = canonicaljson.Canonical(wire)
	if _, err := ParseDecisions(raw); err == nil {
		t.Fatal("duplicate decision accepted")
	}
	for _, bad := range [][]byte{[]byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":null}`), bytes.Replace(raw, []byte(`"action":`), []byte(`"Action":`), 1)} {
		if _, err := ParseDecisions(bad); err == nil {
			t.Fatal("invalid wire accepted")
		}
	}
}
