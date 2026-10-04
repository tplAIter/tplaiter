package ledgerpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectAndHomeClassification(t *testing.T) {
	for rel, want := range map[string]string{
		"project.yaml": "project-marker", "root-template.lock.json": "root-lock", "template.lock.json": "dependency-lock",
		"update.lock": "update-lock", "update/active.json": "update-journal", "update/tx-1/before": "update-cas",
		"new-transaction.pending": "new-pending-marker", "graph-cache/x": "graph-cache", "generators/a/b": "generator-snapshot",
		"anything-else": "opaque",
	} {
		if got := Project(rel).Classification; got != want {
			t.Errorf("Project(%q)=%q want %q", rel, got, want)
		}
	}
	for rel, want := range map[string]string{
		"projects.yaml": "registry", ".lock": "home-lock", "transactions/new.lock": "new-lock",
		"transactions/new/tx-1/active.json": "new-journal", "transactions/new/tx-1/blobs/sha256/ab": "new-cas",
		"transactions/new/tx-1/hooks.lock": "new-hooks-lock", "repos/x/y": "repo-cache", "other": "opaque",
	} {
		if got := Home(rel).Classification; got != want {
			t.Errorf("Home(%q)=%q want %q", rel, got, want)
		}
	}
	for _, rel := range []string{"update.lock", "update/active.json", "new-transaction.pending"} {
		if !Project(rel).Transaction {
			t.Errorf("Project(%q) is not transaction state", rel)
		}
	}
	if Project("baseline.json").Transaction || Home("projects.yaml").Transaction {
		t.Error("a permanent ledger is marked as transaction state")
	}
}

func TestTransactionEvidenceIgnoresPersistentLocksAndFindsDurableEvidence(t *testing.T) {
	for _, rel := range []string{".lock", "update.lock", "transactions/new.lock"} {
		t.Run("persistent "+rel, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := TransactionEvidence(root); err != nil || got != "" {
				t.Fatalf("evidence=%q err=%v, want no evidence", got, err)
			}
		})
	}
	for _, rel := range []string{"update/active.json", "new-transaction.pending", "transactions/new/tx-abc/active.json"} {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := TransactionEvidence(root)
			if err != nil || got != rel {
				t.Fatalf("evidence=%q err=%v, want %q", got, err, rel)
			}
		})
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "projects.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := TransactionEvidence(root); err != nil || got != "" {
		t.Fatalf("clean root evidence=%q err=%v", got, err)
	}
}

func TestTransactionEvidenceRejectsNonDirectoryEntries(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		root := t.TempDir()
		base := filepath.Join(root, "transactions", "new")
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		var err error
		if symlink {
			err = os.Symlink(t.TempDir(), filepath.Join(base, "tx-unknown"))
		} else {
			err = os.WriteFile(filepath.Join(base, "tx-unknown"), nil, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := TransactionEvidence(root); err == nil {
			t.Fatalf("unsafe transaction entry accepted (symlink=%v)", symlink)
		}
	}
}
