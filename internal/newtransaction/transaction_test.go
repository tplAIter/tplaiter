package newtransaction

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/state"
)

func TestAbortRestoresStagedTarget(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("target published before commit: %v", err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "main.go")); err != nil {
		t.Fatal(err)
	}
}

func TestContinueAfterPublishCrashCompletesRegistry(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	regHome := filepath.Join(home, "state")
	if _, _, err := state.EnsureHome(); err != nil {
		_ = err
	}
	if err := os.MkdirAll(regHome, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("version: 1\nitems: []\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareRegistry(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash window after target publication and before registry.
	if err := os.Rename(tx.Workspace(), target); err != nil {
		t.Fatal(err)
	}
	tx.releaseGlobalLock() // simulate process death before recovery
	if err := Continue(home, tx.ID(), regHome); err != nil {
		t.Fatal(err)
	}
	data, exists, _, err := state.ReadProjectsRaw(regHome)
	if err != nil || !exists {
		t.Fatalf("registry read: %v", err)
	}
	if string(data) != string(after) {
		t.Fatalf("registry = %q, want %q", data, after)
	}
	if _, err := os.Stat(filepath.Join(home, "transactions", "new", "tx-"+tx.ID())); !os.IsNotExist(err) {
		t.Fatalf("journal was not collected: %v", err)
	}
}

func TestHookProgressIsRetryableAfterCommit(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	regHome := filepath.Join(home, "state")
	if err := os.MkdirAll(regHome, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("version: 1\nitems: []\n")
	after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareRegistry(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareHooks([]HookEntry{{Kind: "shell", Command: "touch marker"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	called := 0
	if err := tx.RunHooks(context.Background(), func(context.Context, HookEntry) error { called++; return errors.New("temporary") }); err == nil {
		t.Fatal("mandatory hook unexpectedly succeeded")
	}
	if called != 1 {
		t.Fatalf("first hook calls=%d", called)
	}
	if err := tx.RunHooks(context.Background(), func(context.Context, HookEntry) error { called++; return nil }); err != nil {
		t.Fatal(err)
	}
	if called != 2 {
		t.Fatalf("hook replay calls=%d", called)
	}
	if err := tx.Finalize(); err != nil {
		t.Fatal(err)
	}
}

func TestCommitFaultMatrixPreservesPendingInvariant(t *testing.T) {
	points := []string{"commit.before_staging_publish", "commit.after_staging_publish", "commit.before_registry", "commit.after_registry", "commit.before_marker_remove", "commit.after_marker_remove"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(t.TempDir(), "project")
			regHome := filepath.Join(home, "state")
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(regHome, 0o700); err != nil {
				t.Fatal(err)
			}
			before := []byte("version: 1\nitems: []\n")
			after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
			if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
				t.Fatal(err)
			}
			fault := func(got string) error {
				if got == point {
					return ErrInjectedCrash
				}
				return nil
			}
			tx, err := BeginWithFault(home, target, fault)
			if err != nil {
				t.Fatal(err)
			}
			plan := RegistryPlan{Home: regHome, Before: before, After: after}
			if err := tx.PrepareRegistry(plan); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(plan); !errors.Is(err, ErrInjectedCrash) {
				t.Fatalf("commit error=%v", err)
			}
			loaded, err := Load(home, tx.ID())
			if err != nil {
				t.Fatal(err)
			}
			j := loaded.Journal()
			published, _ := os.Stat(target)
			if published != nil {
				if _, markerErr := os.Stat(filepath.Join(target, j.PendingMarker)); markerErr != nil && point != "commit.after_marker_remove" {
					t.Fatalf("published target lacks pending marker after %s: %v", point, markerErr)
				}
			}
			if j.Phase == Complete {
				t.Fatalf("crash point %s exposed complete journal", point)
			}
			// Recovery uses a fresh process object (no fault injector), proving the
			// durable journal—not in-memory state—drives completion.
			if err := Continue(home, tx.ID(), regHome); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(home, "transactions", "new", "tx-"+tx.ID())); !os.IsNotExist(err) {
				t.Fatalf("journal remains after recovery: %v", err)
			}
		})
	}
}

func TestContinueRefusesChangedRegistry(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	regHome := filepath.Join(home, "state")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(regHome, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("version: 1\nitems: []\n")
	after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
	changed := []byte("version: 1\nitems:\n- id: other\n  path: /tmp/other\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: regHome, Before: before, After: after}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tx.Workspace(), target); err != nil {
		t.Fatal(err)
	}
	tx.releaseGlobalLock() // simulate process death before recovery
	if err := state.WriteProjectsRaw(regHome, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Continue(home, tx.ID(), regHome); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("changed registry error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".tplaiter", "new-transaction.pending")); err != nil {
		t.Fatalf("pending marker lost on refusal: %v", err)
	}
}

func TestUnsupportedHookRejectedBeforeCommit(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	var unsupported UnsupportedHookError
	if err := tx.PrepareHooks([]HookEntry{{Kind: "ansible", Command: "post.yml"}}); !errors.As(err, &unsupported) {
		t.Fatalf("error=%v, want UnsupportedHookError", err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "main.go")); err != nil {
		t.Fatal(err)
	}
}

func TestCommitRegistryUsesFinalTargetNotStaging(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "proj")
	regHome := filepath.Join(home, "state")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(regHome, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("version: 1\nitems: []\n")
	after := []byte("version: 1\nitems:\n- id: p\n  path: " + target + "\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareRegistry(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	projects, err := state.LoadProjects(regHome)
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := projects.FindByID("p")
	if !ok {
		t.Fatal("registry entry missing")
	}
	if ref.Path != target {
		t.Fatalf("registry path=%q, want final target %q", ref.Path, target)
	}
	if strings.Contains(ref.Path, ".tplaiter-new-") || strings.Contains(ref.Path, "transactions/new") {
		t.Fatalf("registry retained internal staging path %q", ref.Path)
	}
}

func TestLoadRejectsUnknownAndUnsafeJournalFields(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, "transactions", "new", "tx-"+tx.ID(), "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unexpected"] = true
	data, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "transactions", "new", "tx-"+tx.ID(), "active.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home, tx.ID()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Load error=%v, want ErrUnsafe", err)
	}
}

func TestCommitPersistsCommittedBeforeRemovingPendingMarker(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	regHome := filepath.Join(home, "state")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(regHome, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("version: 1\nitems: []\n")
	after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginWithFault(home, target, func(point string) error {
		if point == "commit.before_marker_remove" {
			return ErrInjectedCrash
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: regHome, Before: before, After: after}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(plan); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("Commit error=%v", err)
	}
	loaded, err := Load(home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Journal().Phase; got != Committed {
		t.Fatalf("phase=%q, want committed", got)
	}
	if _, err := os.Stat(filepath.Join(target, ".tplaiter", "new-transaction.pending")); err != nil {
		t.Fatalf("pending marker disappeared before committed recovery: %v", err)
	}
	if err := Continue(home, tx.ID(), regHome); err != nil {
		t.Fatal(err)
	}
}

func TestCommitRejectsRegistryHomeSubstitution(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	regHome := filepath.Join(home, "state")
	otherHome := filepath.Join(home, "other-state")
	for _, dir := range []string{target, regHome, otherHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	before := []byte("version: 1\nitems: []\n")
	after := []byte("version: 1\nitems:\n- id: p\n  path: /tmp/p\n")
	if err := state.WriteProjectsRaw(regHome, before, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := Begin(home, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareRegistry(RegistryPlan{Home: regHome, Before: before, After: after}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(RegistryPlan{Home: otherHome, Before: before, After: after}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Commit error=%v, want ErrUnsafe", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("target published after rejected registry substitution: %v", err)
	}
}

func TestHookDigestTamperingIsRejectedBeforeExecution(t *testing.T) {
	tx := &Transaction{j: Journal{Phase: Committed, Hooks: HookProgress{Plan: []HookEntry{{Kind: "shell", Command: "safe", Digest: digest([]byte("shell\x00safe"))}}}}}
	tx.j.Hooks.Plan[0].Command = "unsafe"
	called := false
	if err := tx.RunHooks(context.Background(), func(context.Context, HookEntry) error { called = true; return nil }); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("RunHooks error=%v, want ErrUnsafe", err)
	}
	if called {
		t.Fatal("tampered hook executed")
	}
}

func TestBeginRefusesTemplateControlledStateDirSymlink(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	outside := t.TempDir()
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, ".tplaiter")); err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(home, target); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Begin error=%v, want ErrUnsafe", err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("target was not restored after refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "new-transaction.pending")); !os.IsNotExist(err) {
		t.Fatalf("marker escaped through template symlink: %v", err)
	}
}

func TestInventoryAndGCPreserveUnsafeEvidence(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "transactions", "new", "tx-"+strings.Repeat("a", 32))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.json"), []byte(`{"apiVersion":"future"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := Inventory(home)
	if err != nil || len(items) != 1 || items[0].Status != "unsafe" {
		t.Fatalf("inventory=%+v err=%v", items, err)
	}
	plan, err := PlanGC(home, time.Now().UTC(), true)
	if err != nil || len(plan.IDs) != 0 {
		t.Fatalf("gc plan=%+v err=%v", plan, err)
	}
	if err := ExecuteGC(home, GCPlan{IDs: []string{strings.Repeat("a", 32)}, DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("unsafe evidence removed: %v", err)
	}
}

func TestGlobalLockSerializesPrepareThroughCommit(t *testing.T) {
	home := t.TempDir()
	targetOne := filepath.Join(t.TempDir(), "one")
	targetTwo := filepath.Join(t.TempDir(), "two")
	for _, target := range []string{targetOne, targetTwo} {
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := Begin(home, targetOne)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(home, targetTwo); !errors.Is(err, ErrActive) {
		t.Fatalf("second Begin error=%v, want ErrActive", err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	if tx2, err := Begin(home, targetTwo); err != nil {
		t.Fatalf("Begin after first abort: %v", err)
	} else if err := tx2.Abort(); err != nil {
		t.Fatal(err)
	}
}
