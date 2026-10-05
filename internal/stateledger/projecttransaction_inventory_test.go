package stateledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExistingTreeNamespacesAppearInLedger(t *testing.T) {
	project, home := t.TempDir(), t.TempDir()
	id := strings.Repeat("a", 32)
	files := map[string]string{
		filepath.Join(project, StateDir, "project-transactions", id, "000001"): "old owned bytes",
		filepath.Join(home, "transactions/project", "tx-"+id, "plan.json"):     "unsigned plan",
		filepath.Join(home, "transactions/project", "tx-"+id, "state.json"):    "unsigned terminal claim",
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := Inventory(project, Options{HomeRoot: home, SecretProvider: &testSecrets{}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		StateDir + "/project-transactions/" + id + "/000001": "project-transaction-image",
		"transactions/project/tx-" + id + "/plan.json":       "project-transaction-plan",
		"transactions/project/tx-" + id + "/state.json":      "project-transaction-state",
	}
	for _, entry := range snapshot.Entries {
		kind, ok := want[entry.Path]
		if !ok {
			continue
		}
		if entry.Classification != kind || entry.Retention != "preserve" || entry.Owner != "project-transaction-engine" {
			t.Fatalf("entry %+v", entry)
		}
		delete(want, entry.Path)
	}
	if len(want) != 0 || len(snapshot.ProjectTransactionCandidates) != 2 {
		t.Fatalf("missing classifications: %+v %+v", want, snapshot.ProjectTransactionCandidates)
	}
	if len(snapshot.Transactions) != 0 {
		t.Fatal("project journal fell through creation inventory")
	}
	for name, content := range files {
		raw, err := os.ReadFile(name)
		if err != nil || string(raw) != content {
			t.Fatal("ledger altered evidence", err)
		}
	}
}
