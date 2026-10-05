package ledgerpath

import (
	"strings"
	"testing"
)

func TestProjectTransactionNamespaces(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, tc := range []struct {
		rel, want string
		home      bool
	}{
		{"transactions/project/tx-" + id + "/plan.json", "project-transaction-plan", true},
		{"transactions/project/tx-" + id + "/state.json", "project-transaction-state", true},
		{"transactions/project/tx-" + id + "/active.json", "project-transaction-opaque", true},
		{"transactions/project/tx-foreign/state.json", "project-transaction-opaque", true},
		{"transactions/project/tx-" + strings.ToUpper(id) + "/state.json", "project-transaction-opaque", true},
		{"transactions/project/tx-" + id + "/../state.json", "project-transaction-opaque", true},
		{"project-transactions/" + id + "/000001", "project-transaction-image", false},
		{"project-transactions/" + id + "/1000000", "project-transaction-image", false},
		{"project-transactions/" + id + "/0000001", "project-transaction-opaque", false},
		{"project-transactions/" + id + "/000001/foreign", "project-transaction-opaque", false},
		{"project-transactions/foreign/000001", "project-transaction-opaque", false},
	} {
		var c Class
		var ok bool
		if tc.home {
			c, ok = HomeProjectTransaction(tc.rel)
		} else {
			c, ok = ProjectTransactionImage(tc.rel)
		}
		if !ok || c.Classification != tc.want || !c.Transaction || c.Retention != "preserve" {
			t.Fatalf("%s: %+v %v", tc.rel, c, ok)
		}
		if strings.Contains(c.Classification, "cas") {
			t.Fatal("inode slot incorrectly called CAS")
		}
	}
	for _, rel := range []string{"transactions/new/tx-" + id + "/active.json", "transactions/project-other/a", "projects.yaml"} {
		if _, ok := HomeProjectTransaction(rel); ok {
			t.Fatal("foreign namespace adopted", rel)
		}
	}
	if _, ok := ProjectTransactionImage("generators/a"); ok {
		t.Fatal("generator snapshot adopted")
	}
}
