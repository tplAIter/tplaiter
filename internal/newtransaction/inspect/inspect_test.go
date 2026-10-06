package inspect_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/newtransaction/inspect"
)

func TestInspectNoncreatingAndClosedOwnerParity(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := newtransaction.BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("signed image")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx.Release()
	journalPath := filepath.Join(home, "transactions", "new", "tx-"+tx.ID(), "active.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	record, err := inspect.Load(home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	if record.Journal().ID != tx.ID() || record.Journal().Phase != inspect.Prepared || record.Journal().Target != target {
		t.Fatal("lost observed geometry")
	}
	warm, _ := json.MarshalIndent(tx.Journal(), "", "  ")
	cold, _ := json.MarshalIndent(record.Journal(), "", "  ")
	if !bytes.Equal(before, warm) || !bytes.Equal(warm, cold) {
		t.Fatal("ordinary journal bytes changed")
	}
	entries, err := inspect.Inventory(home)
	if err != nil || len(entries) != 1 {
		t.Fatalf("inventory: %v %v", entries, err)
	}
	stat, err := os.Stat(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].ID != tx.ID() || entries[0].Status != inspect.StatusActive || entries[0].Reason != "" || !entries[0].UpdatedAt.Equal(stat.ModTime().UTC()) {
		t.Fatalf("inventory semantics changed: %+v", entries)
	}
	again, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(again, before) {
		t.Fatal("read modified journal")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{"future", func(b []byte) []byte {
			return bytes.Replace(b, []byte(inspect.APIVersion), []byte("tplaiter.dev/new-transaction/v9"), 1)
		}, inspect.ErrFutureVersion},
		{"unknown-field", func(b []byte) []byte { return append([]byte(`{"callerAuthority":true,`), b[1:]...) }, inspect.ErrUnsafe},
		{"unknown-phase", func(b []byte) []byte { return bytes.Replace(b, []byte(`"prepared"`), []byte(`"invented"`), 1) }, inspect.ErrUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(journalPath, tc.mutate(before), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := inspect.Load(home, tx.ID()); !errors.Is(err, tc.want) {
				t.Fatalf("accepted malformed journal: %v", err)
			}
			if err := os.WriteFile(journalPath, before, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	absent := filepath.Join(t.TempDir(), "absent-home")
	if got, err := inspect.Inventory(absent); err != nil || len(got) != 0 {
		t.Fatalf("absent inventory: %v %v", got, err)
	}
	if _, err := inspect.Load(absent, "0123456789abcdef0123456789abcdef"); !errors.Is(err, inspect.ErrNoActive) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		t.Fatal("inspection created home")
	}
}

func TestInspectCASRefusesAliasesAndUnsafeModes(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "cas")
	if err := os.WriteFile(file, []byte("immutable evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.ReadCASFile(file); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.ReadCASFile(file); !errors.Is(err, inspect.ErrUnsafe) {
		t.Fatalf("hardlink admitted: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.ReadCASFile(file); !errors.Is(err, inspect.ErrUnsafe) {
		t.Fatalf("public evidence admitted: %v", err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.ReadCASFile(link); !errors.Is(err, inspect.ErrUnsafe) {
		t.Fatalf("symlink admitted: %v", err)
	}
}

func TestInspectRetainsUncertainTreesAndMissingCAS(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := newtransaction.BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("signed")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx.Release()
	foreign := filepath.Join(tx.Workspace(), "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := inspect.Inventory(home)
	if err != nil || len(entries) != 1 || entries[0].Status != "ownership_uncertain" || entries[0].Reason != inspect.ErrOwnershipUncertain.Error() {
		t.Fatalf("uncertain: %v %v", entries, err)
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "keep" {
		t.Fatal("inspection altered foreign content")
	}
	ref := tx.Journal().TargetAfterSHA
	blob := filepath.Join(home, "transactions", "new", "tx-"+tx.ID(), "blobs", "sha256", ref[len("sha256:"):])
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.Load(home, tx.ID()); !errors.Is(err, inspect.ErrMissingCAS) {
		t.Fatal(err)
	}
	got, err := inspect.Inventory(home)
	if err != nil || len(got) != 1 || got[0].Status != inspect.StatusMissingCAS || got[0].Reason != inspect.ErrMissingCAS.Error() {
		t.Fatalf("missing: %v %v", got, err)
	}
	// Alias compatibility preserves the existing Snapshot element contract.
	var old []newtransaction.TransactionStatus = got
	if !reflect.DeepEqual(old, got) {
		t.Fatal("status type changed")
	}
}
