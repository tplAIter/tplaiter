package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryPreservesEvidenceWithoutAuthority(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project, home := filepath.Join(base, "project"), filepath.Join(base, "home")
	id := strings.Repeat("a", 32)
	for _, name := range []string{filepath.Join(project, ".tplaiter/project-transactions", id), filepath.Join(home, "transactions/project", "tx-"+id), filepath.Join(home, "transactions/new/tx-generic")} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Receipt contents are deliberately unreadable and unsigned. Discovery must
	// neither open these bytes nor report authenticated committed status.
	receipt := filepath.Join(home, "transactions/project", "tx-"+id, "state.json")
	if err := os.WriteFile(receipt, []byte(`{"phase":"committed"}`), 0o000); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(receipt)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(home, "transactions/project/foreign")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o640); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(project, ".tplaiter/project-transactions/foreign-link")
	if err := os.Symlink(home, symlink); err != nil {
		t.Fatal(err)
	}
	got, err := Discover(context.Background(), project, home)
	if err != nil || len(got) != 4 {
		t.Fatalf("discovery: %+v %v", got, err)
	}
	for _, candidate := range got {
		if strings.Contains(candidate.Path, "transactions/new/") {
			t.Fatal("generic namespace inventoried")
		}
		if candidate.ID == id && (!candidate.CanonicalID || !candidate.Directory) {
			t.Fatal("canonical directory lost")
		}
		if candidate.ID == "foreign" && (candidate.CanonicalID || candidate.Directory) {
			t.Fatal("foreign file concealed")
		}
		if candidate.ID == "foreign-link" && (!candidate.Symlink || candidate.Directory) {
			t.Fatal("symlink followed")
		}
	}
	after, err := os.Lstat(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("discovery mutated receipt")
	}
	if (Record{}).Status() != StatusUnverified {
		t.Fatal("zero record falsely terminal")
	}
	r := Record{issues: []Status{StatusMissingCAS, StatusMissingImages}}
	detached := r.Issues()
	detached[0] = StatusCommitted
	if r.Issues()[0] != StatusMissingCAS || r.Issues()[1] != StatusMissingImages {
		t.Fatal("issues alias or evidence conflation")
	}
}

func TestDiscoveryRefusesSymlinkRootAndParent(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	actualRoot := filepath.Join(base, "real")
	if err := os.Mkdir(actualRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(actualRoot, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), alias, ""); !errors.Is(err, ErrUnsafeDiscovery) {
		t.Fatal("root symlink accepted", err)
	}
	if err := os.Symlink(actualRoot, filepath.Join(actualRoot, ".tplaiter")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), actualRoot, ""); !errors.Is(err, ErrUnsafeDiscovery) {
		t.Fatal("namespace symlink accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, actualRoot, ""); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := Discover(context.Background(), "relative", ""); !errors.Is(err, ErrUnsafeDiscovery) {
		t.Fatal("relative root accepted", err)
	}
}
