package localbaseline

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func validLineage(t *testing.T) []byte {
	t.Helper()
	w := wireLineage{APIVersion: APIVersion, Domain: Domain, Operation: "rebaseline", Sequence: 1, OriginalState: "absent", PredecessorState: "absent", Selected: []SelectedIdentity{{Path: "ordinary.txt", Device: 1, Inode: 2, Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Mode: 0o644}}, Protection: []Protection{{Path: "ordinary.txt", Reason: "user-owned"}}}
	raw, err := canonicaljson.Canonical(w)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeLineageClosedTransitionGrammar(t *testing.T) {
	var baseline wireLineage
	if err := canonicaljson.DecodeStrict(validLineage(t), &baseline); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*wireLineage){
		"later-without-predecessor": func(w *wireLineage) { w.Sequence = 2 },
		"too-many-transitions":      func(w *wireLineage) { w.Sequence = 33 },
		"first-with-predecessor": func(w *wireLineage) {
			w.PredecessorState = "present"
			w.Predecessor = &ReceiptRef{ID: strings.Repeat("a", 32), PlanDigest: w.Selected[0].Digest, ReceiptDigest: w.Selected[0].Digest}
		},
		"unsorted-selected": func(w *wireLineage) {
			w.Selected = append(w.Selected, SelectedIdentity{Path: "a.txt", Device: 1, Inode: 3, Digest: w.Selected[0].Digest, Mode: 0o644})
		},
		"duplicate-protection": func(w *wireLineage) { w.Protection = append(w.Protection, w.Protection[0]) },
		"unknown-protection":   func(w *wireLineage) { w.Protection[0].Reason = "caller-choice" },
		"uppercase-digest":     func(w *wireLineage) { w.Selected[0].Digest = "sha256:" + strings.Repeat("A", 64) },
		"invalid-origin-digest": func(w *wireLineage) {
			w.OriginalState = "present"
			w.OriginalOrigin = &Origin{ProjectID: "project", Decision: "not-a-digest"}
		},
		"selected-count": func(w *wireLineage) { w.Selected = make([]SelectedIdentity, MaxSelected+1) },
	} {
		t.Run(name, func(t *testing.T) {
			var w wireLineage
			canonicaljson.DecodeStrict(validLineage(t), &w)
			change(&w)
			raw, err := canonicaljson.Canonical(w)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeLineage(raw); err == nil {
				t.Fatal("invalid transition accepted")
			}
		})
	}
	// The 1 MiB limit is enforced before parsing, rather than using a 32 MiB
	// chain total as the limit for one transition.
	if _, err := DecodeLineage([]byte(strings.Repeat(" ", MaxMetadataBytes+1))); err == nil {
		t.Fatal("per-transition bound ignored")
	}
	baseline.Sequence = 2
	baseline.PredecessorState = "present"
	baseline.Predecessor = &ReceiptRef{ID: strings.Repeat("a", 32), PlanDigest: baseline.Selected[0].Digest, ReceiptDigest: baseline.Selected[0].Digest}
	raw, err := canonicaljson.Canonical(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLineage(raw); err != nil {
		t.Fatal("explicit predecessor rejected", err)
	}
}

func TestDecodeLineageCanonicalDetachedData(t *testing.T) {
	raw := validLineage(t)
	l, err := DecodeLineage(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Canonical()
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("canonical round trip: %v", err)
	}
	selected := l.Selected()
	selected[0].Path = "changed"
	if l.Selected()[0].Path == "changed" {
		t.Fatal("selected identity was mutable")
	}
	if l.OriginalOriginPresent() || l.PredecessorPresent() {
		t.Fatal("absence discriminator changed")
	}
}

func TestDecodeLineageRejectsUnknownDuplicateAndLimits(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/local-baseline-lineage/v1","domain":"tplaiter.dev/local-baseline-lineage/v1","operation":"rebaseline","sequence":1,"originalOriginState":"absent","predecessorState":"absent","selected":[],"protection":[],"extra":1}`),
		[]byte(`{"apiVersion":"tplaiter.dev/local-baseline-lineage/v1","apiVersion":"tplaiter.dev/local-baseline-lineage/v1","domain":"tplaiter.dev/local-baseline-lineage/v1","operation":"rebaseline","sequence":1,"originalOriginState":"absent","predecessorState":"absent","selected":[],"protection":[]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/local-baseline-lineage/v1","domain":"tplaiter.dev/local-baseline-lineage/v1","operation":"rebaseline","sequence":1,"originalOriginState":"present","predecessorState":"absent","selected":[],"protection":[]}`),
	} {
		if _, err := DecodeLineage(raw); err == nil {
			t.Fatal("invalid lineage accepted")
		}
	}
}
