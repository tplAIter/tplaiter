package exports

import (
	"context"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/deps"
	"testing"
)

func TestAuthoredProjectionRequiresActualOpaqueSources(t *testing.T) {
	raw, e := json.Marshal(authoredFixture())
	if e != nil {
		t.Fatal(e)
	}
	for _, sources := range [][]*deps.VerifiedSource{nil, {nil}, {&deps.VerifiedSource{}}} {
		if _, e := ProjectAuthoredModifier(context.Background(), raw, "root", sources); e == nil {
			t.Fatal("caller fabricated source admitted")
		}
	}
	if _, _, e := (&ProjectedModifier{}).Data(context.Background()); e == nil {
		t.Fatal("zero projection accepted")
	}
}
func TestStableAuthorConstraintExcludesRuntimeCustody(t *testing.T) {
	a := deps.PinnedSource{Alias: "root", ProviderID: "label-a", EvidenceDigest: "runtime-a", RequestedRef: "label-ref", Parameters: []deps.Parameter{}, Dependencies: []string{}}
	b := a
	b.ProviderID = "label-b"
	b.EvidenceDigest = "runtime-b"
	b.RequestedRef = "another-label"
	x, _ := json.Marshal(stableSource(a))
	y, _ := json.Marshal(stableSource(b))
	if string(x) != string(y) {
		t.Fatal("runtime custody leaked into authored equality")
	}
	b.ContentDigest = "changed"
	y, _ = json.Marshal(stableSource(b))
	if string(x) == string(y) {
		t.Fatal("content omitted")
	}
}
