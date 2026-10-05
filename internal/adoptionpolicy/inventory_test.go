package adoptionpolicy

import (
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"testing"
)

func TestStrictWriterPartitionNeverRebaselinesExcludedDesired(t *testing.T) {
	p := testPolicy(t)
	for _, files := range []map[string][]byte{{"go.mod": []byte("signed"), "missing.txt": []byte("signed missing"), "tracked.txt": []byte("signed tracked")}, {"tracked.txt": []byte("next")}, {"go.mod": []byte("reintroduced"), "missing.txt": []byte("changed"), "tracked.txt": []byte("next")}} {
		inv, e := Inventory(files, p)
		if e != nil {
			t.Fatal(e)
		}
		if len(inv.Artifacts) != 1 || inv.Artifacts[0].Path != "tracked.txt" || len(inv.Skipped) != 2 || len(inv.Tombstones) != 1 {
			t.Fatalf("partition %#v", inv)
		}
		raw, _ := canonicaljson.Canonical(inv)
		if ValidateInventory(raw, files, p) != nil {
			t.Fatal("valid partition rejected")
		}
		for _, bad := range []func(*ownership.Inventory){func(i *ownership.Inventory) { i.Artifacts = append(i.Artifacts, ownership.Artifact{Path: "go.mod"}) }, func(i *ownership.Inventory) { i.Tombstones = nil }, func(i *ownership.Inventory) { i.Skipped[0].Reason = "skipIfExists" }, func(i *ownership.Inventory) { i.Skipped = append(i.Skipped, i.Skipped[0]) }} {
			copy, e := Inventory(files, p)
			if e != nil {
				t.Fatal(e)
			}
			bad(&copy)
			raw, _ := canonicaljson.Canonical(copy)
			if ValidateInventory(raw, files, p) == nil {
				t.Fatal("contradictory ownership accepted")
			}
		}
	}
}
