package managedblocks

import "testing"

func TestBaselineRejectsInvalidTombstone(t *testing.T) {
	b, err := BuildBaseline(map[string][]byte{"a.go": managed("a", "root", "x\n")}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := b.Files["a.go"]
	x := f.Blocks["a"]
	x.State = StateLocalDeleted
	f.Blocks["a"] = x
	b.Files["a.go"] = f
	if b.Validate() == nil {
		t.Fatal("state without tombstone accepted")
	}
}
