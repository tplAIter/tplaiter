package newtransaction

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
)

func TestSealedOutputsCannotAdoptMutableStage(t *testing.T) {
	for _, drift := range []string{"bytes", "mode", "extra"} {
		t.Run(drift, func(t *testing.T) {
			home, target := t.TempDir(), t.TempDir()
			files := map[string][]byte{"hello.txt": []byte("approved")}
			tx, err := BeginSealedWithFault(home, target, files, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Release()
			// Altering the caller's buffers after Begin cannot change authority.
			files["hello.txt"][0] = 'X'
			name := filepath.Join(tx.Workspace(), "hello.txt")
			if err := os.WriteFile(name, []byte("approved"), 0o644); err != nil {
				t.Fatal(err)
			}
			switch drift {
			case "bytes":
				err = os.WriteFile(name, []byte("unapproved"), 0o644)
			case "mode":
				err = os.Chmod(name, 0o755)
			case "extra":
				err = os.WriteFile(filepath.Join(tx.Workspace(), "foreign"), []byte("keep"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := tx.Journal().TargetAfterSHA
			if err := tx.SealOutputs(); !errors.Is(err, ErrOwnershipUncertain) {
				t.Fatalf("adopted observed tree: %v", err)
			}
			if err := tx.Abort(); !errors.Is(err, ErrOwnershipUncertain) {
				t.Fatalf("abort deleted unowned stage: %v", err)
			}
			loaded, err := Load(home, tx.ID())
			if err != nil || loaded.Journal().TargetAfterSHA != before || loaded.sealedReady {
				t.Fatalf("seal changed on refusal: %v", err)
			}
			if _, err := os.Stat(name); err != nil {
				t.Fatal("ambiguous content removed")
			}
		})
	}
}

func TestSealedAbortRestoresOnlyProvenOwnedTree(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("approved")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "hello.txt"), []byte("approved"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned abort did not restore empty target: %v %v", entries, err)
	}
}

func TestSealedCommittedRecoveryRetainsChangedTree(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	tx, err := BeginSealedWithFault(home, target, map[string][]byte{"hello.txt": []byte("approved")}, func(point string) error {
		if point == "commit.before_marker_remove" {
			return ErrInjectedCrash
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "hello.txt"), []byte("approved"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.SealOutputs(); err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: home, After: []byte("version: 1\nitems: []\n")}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(plan); !errors.Is(err, ErrInjectedCrash) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "hello.txt"), []byte("foreign edit"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Continue(home, tx.ID(), home); !errors.Is(err, ErrOwnershipUncertain) {
		t.Fatalf("recovery finalized changed afterimage: %v", err)
	}
	if err := tx.Finalize(); !errors.Is(err, ErrOwnershipUncertain) {
		t.Fatalf("finalize removed evidence of drift: %v", err)
	}
	raw, err := os.ReadFile(state.ProjectsPath(home))
	if err != nil || !bytes.Equal(raw, plan.After) {
		t.Fatal("committed registry changed")
	}
	if _, err := Load(home, tx.ID()); err != nil {
		t.Fatal("lost committed recovery journal")
	}
}
