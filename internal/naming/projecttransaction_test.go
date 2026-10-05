package naming

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeRelocationRecheckedUnderHomeWriterLock(t *testing.T) {
	parent := t.TempDir()
	old := filepath.Join(parent, "old")
	dest := filepath.Join(parent, "new")
	writeLegacyHome(t, old)
	plan, err := PlanRoots([]Root{{Kind: "home", SourceRoot: old, DestinationRoot: dest}})
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(old, "transactions/project/tx-00112233445566778899aabbccddeeff")
	if err := os.MkdirAll(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(journal, "state.json")
	raw := []byte("opaque receipt; naming must never decode/grant it")
	if err := os.WriteFile(receipt, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(plan); !errors.Is(err, ErrNativeRelocation) {
		t.Fatalf("fresh check: %v", err)
	}
	after, err := os.Stat(receipt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || string(got) != string(raw) {
		t.Fatal("refusal changed receipt")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("destination created")
	}
	if _, err := PlanRoots([]Root{{Kind: "home", SourceRoot: old, DestinationRoot: dest}}); !errors.Is(err, ErrNativeRelocation) {
		t.Fatalf("planning: %v", err)
	}
}
