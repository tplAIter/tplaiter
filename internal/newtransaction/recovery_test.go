package newtransaction

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/state"
)

const (
	crashChildEnv = "TPLAITER_NEWTX_CRASH_CHILD"
	crashExitCode = 3
)

var (
	registryBefore = []byte("version: 1\nitems: []\n")
	registryAfter  = []byte("version: 1\nitems:\n- id: p\n  path: /workspace/p\n")
)

// crashFixture is one home/target/registry triple used by the recovery tests.
type crashFixture struct {
	home, target, registry string
}

func newCrashFixture(t *testing.T) crashFixture {
	t.Helper()
	f := crashFixture{home: t.TempDir(), target: filepath.Join(t.TempDir(), "project"), registry: filepath.Join(t.TempDir(), "state")}
	if err := os.MkdirAll(f.target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.target, "main.go"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.registry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteProjectsRaw(f.registry, registryBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// runScenario drives one complete new transaction. fault is consulted at every
// failpoint.
func (f crashFixture) runScenario(fault FaultInjector) error {
	tx, err := BeginWithFault(f.home, f.target, fault)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "generated.txt"), []byte("rendered"), 0o644); err != nil {
		return err
	}
	plan := RegistryPlan{Home: f.registry, Before: registryBefore, After: registryAfter}
	if err := tx.PrepareRegistry(plan); err != nil {
		return err
	}
	if err := tx.PrepareHooks([]HookEntry{{Kind: "shell", Command: "true"}}); err != nil {
		return err
	}
	if err := tx.Commit(plan); err != nil {
		return err
	}
	if err := tx.RunHooks(context.Background(), func(context.Context, HookEntry) error { return nil }); err != nil {
		return err
	}
	return tx.Finalize()
}

// crashPoints lists every durable boundary of the scenario, in order.
var crashPoints = []string{
	"begin.before_journal", "begin.after_journal", "begin.after_stage", "begin.after_marker",
	"commit.before_journal", "commit.before_staging_publish", "commit.after_staging_publish",
	"commit.before_registry", "commit.after_registry", "commit.before_marker_remove", "commit.after_marker_remove",
	"hooks.before_run.0", "hooks.after_run.0", "hooks.before_checkpoint.0", "finalize.before_journal",
}

// TestCrashChild is the re-executed child of TestKilledProcessRecoversAtEveryFailpoint.
// It terminates the process with os.Exit at the requested failpoint, so no
// deferred cleanup, lock release or in-memory state survives: recovery sees
// exactly what a killed process leaves on disk.
func TestCrashChild(t *testing.T) {
	spec := os.Getenv(crashChildEnv)
	if spec == "" {
		t.Skip("helper process for TestKilledProcessRecoversAtEveryFailpoint")
	}
	parts := strings.Split(spec, "\x1f")
	f := crashFixture{home: parts[0], target: parts[1], registry: parts[2]}
	point := parts[3]
	err := f.runScenario(func(got string) error {
		if got == point {
			os.Exit(crashExitCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scenario failed before reaching %s: %v", point, err)
	}
	t.Fatalf("failpoint %s was never reached", point)
}

func TestKilledProcessRecoversAtEveryFailpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns one process per failpoint")
	}
	for _, point := range crashPoints {
		t.Run(point, func(t *testing.T) {
			f := newCrashFixture(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), crashChildEnv+"="+strings.Join([]string{f.home, f.target, f.registry, point}, "\x1f"))
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != crashExitCode {
				t.Fatalf("child did not die at %s: err=%v output=%s", point, err, out)
			}
			recoverAndAssert(t, f)
		})
	}
}

// recoverAndAssert applies the documented recovery rule: a prepared journal is
// aborted, anything later is continued. Afterwards the target and registry
// must be exactly the before image (abort) or the after image (continue), and
// no journal may remain.
func recoverAndAssert(t *testing.T, f crashFixture) {
	t.Helper()
	items, err := Inventory(f.home)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) > 1 {
		t.Fatalf("inventory=%+v, want at most one record", items)
	}
	aborted := true
	if len(items) == 1 {
		item := items[0]
		switch item.Status {
		case StatusOrphan:
			plan, err := PlanGC(f.home, time.Now().Add(GCRetention+time.Hour), false)
			if err != nil || !slices.Contains(plan.IDs, item.ID) {
				t.Fatalf("orphan not collectable: plan=%+v err=%v", plan, err)
			}
			if err := os.RemoveAll(filepath.Join(f.home, "transactions", "new", "tx-"+item.ID)); err != nil {
				t.Fatal(err)
			}
		case StatusActive:
			tx, err := Load(f.home, item.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tx.Journal().Phase == Prepared {
				if err := AbortByID(f.home, item.ID); err != nil {
					t.Fatalf("abort: %v", err)
				}
			} else {
				aborted = false
				hooks := 0
				if err := ContinueWithHooks(context.Background(), f.home, item.ID, f.registry, func(context.Context, HookEntry) error { hooks++; return nil }); err != nil {
					t.Fatalf("continue: %v", err)
				}
			}
		default:
			t.Fatalf("unexpected recovery status %+v", item)
		}
	}
	if items, err := Inventory(f.home); err != nil || len(items) != 0 {
		t.Fatalf("journal remains after recovery: %+v err=%v", items, err)
	}
	registry, _, _, err := state.ReadProjectsRaw(f.registry)
	if err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(filepath.Join(f.target, "main.go"))
	if err != nil || string(main) != "original" {
		t.Fatalf("user file lost: %q err=%v", main, err)
	}
	if _, err := os.Stat(filepath.Join(f.target, ".tplaiter", "new-transaction.pending")); !os.IsNotExist(err) {
		t.Fatalf("pending marker survived recovery: %v", err)
	}
	_, generatedErr := os.Stat(filepath.Join(f.target, "generated.txt"))
	if aborted {
		if string(registry) != string(registryBefore) || !os.IsNotExist(generatedErr) {
			t.Fatalf("abort did not restore the before image: registry=%q generated=%v", registry, generatedErr)
		}
	} else if string(registry) != string(registryAfter) || generatedErr != nil {
		t.Fatalf("continue did not publish the after image: registry=%q generated=%v", registry, generatedErr)
	}
	entries, err := os.ReadDir(filepath.Dir(f.target))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), stagingInfix) {
			t.Fatalf("staging directory survived recovery: %s", entry.Name())
		}
	}
}

func TestAbortRestoresTargetAfterEveryBeginFailpoint(t *testing.T) {
	for _, point := range []string{"begin.before_journal", "begin.after_journal", "begin.after_stage", "begin.after_marker"} {
		t.Run(point, func(t *testing.T) {
			f := newCrashFixture(t)
			err := f.runScenario(func(got string) error {
				if got == point {
					return ErrInjectedCrash
				}
				return nil
			})
			if !errors.Is(err, ErrInjectedCrash) {
				t.Fatalf("scenario error=%v", err)
			}
			recoverAndAssert(t, f)
		})
	}
}

func TestInventoryClassifiesActiveFutureMissingCASAndUnsafe(t *testing.T) {
	home := t.TempDir()
	begin := func() *Transaction {
		t.Helper()
		target := filepath.Join(t.TempDir(), "project")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		tx, err := Begin(home, target)
		if err != nil {
			t.Fatal(err)
		}
		tx.releaseGlobalLock()
		return tx
	}
	active := begin()
	future := begin()
	journal := filepath.Join(home, "transactions", "new", "tx-"+future.ID(), "active.json")
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), APIVersion, "tplaiter.dev/new-transaction/v2", 1))
	if err := os.WriteFile(journal, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := begin()
	manifest := filepath.Join(home, "transactions", "new", "tx-"+missing.ID(), "blobs", "sha256", casLeaf(missing.Journal().TargetAfterSHA))
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	unsafe := begin()
	if err := os.WriteFile(filepath.Join(home, "transactions", "new", "tx-"+unsafe.ID(), "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := Inventory(home)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range items {
		got[item.ID] = item.Status
	}
	want := map[string]string{active.ID(): StatusActive, future.ID(): StatusFuture, missing.ID(): StatusMissingCAS, unsafe.ID(): StatusUnsafe}
	for id, status := range want {
		if got[id] != status {
			t.Fatalf("status[%s]=%q want %q (all=%+v)", id, got[id], status, items)
		}
	}
	plan, err := PlanGC(home, time.Now().Add(365*24*time.Hour), false)
	if err != nil || len(plan.IDs) != 0 {
		t.Fatalf("GC selected preserved evidence: %+v err=%v", plan, err)
	}
	if _, err := Load(home, future.ID()); !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("future Load error=%v", err)
	}
	if _, err := Load(home, missing.ID()); !errors.Is(err, ErrMissingCAS) {
		t.Fatalf("missing-CAS Load error=%v", err)
	}
}

func TestSelectGCKeepsNewestHundredWithinThirtyDays(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	var items []TransactionStatus
	id := func(i int) string {
		return strings.Repeat("0", 29) + string(rune('a'+i/100)) + string(rune('a'+i/10%10)) + string(rune('a'+i%10))
	}
	for i := range 105 {
		items = append(items, TransactionStatus{ID: id(i), Status: StatusComplete, UpdatedAt: now.Add(-time.Duration(i) * time.Minute)})
	}
	items = append(
		items,
		TransactionStatus{ID: id(200), Status: StatusAborted, UpdatedAt: now.Add(-31 * 24 * time.Hour)},
		TransactionStatus{ID: id(201), Status: StatusActive, UpdatedAt: now.Add(-365 * 24 * time.Hour)},
		TransactionStatus{ID: id(202), Status: StatusUnsafe, UpdatedAt: now.Add(-365 * 24 * time.Hour)},
		TransactionStatus{ID: id(203), Status: StatusOrphan, UpdatedAt: now.Add(-time.Hour)},
		TransactionStatus{ID: id(204), Status: StatusOrphan, UpdatedAt: now.Add(-31 * 24 * time.Hour)},
	)
	got := selectGC(items, now)
	want := []string{id(100), id(101), id(102), id(103), id(104), id(200), id(204)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("selected=%v want %v", got, want)
	}
}

func TestExecuteGCRemovesOnlyStillEligibleTerminalJournals(t *testing.T) {
	f := newCrashFixture(t)
	terminal := func(created time.Time) string {
		t.Helper()
		target := filepath.Join(t.TempDir(), "project")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		tx, err := Begin(f.home, target)
		if err != nil {
			t.Fatal(err)
		}
		before, _, _, err := state.ReadProjectsRaw(f.registry)
		if err != nil {
			t.Fatal(err)
		}
		plan := RegistryPlan{Home: f.registry, Before: before, After: before}
		if err := tx.PrepareRegistry(plan); err != nil {
			t.Fatal(err)
		}
		if err := tx.PrepareHooks([]HookEntry{{Kind: "shell", Command: "true"}}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(plan); err != nil {
			t.Fatal(err)
		}
		tx.j.Phase = Complete
		if err := tx.save(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filepath.Join(tx.dir, "active.json"), created, created); err != nil {
			t.Fatal(err)
		}
		return tx.ID()
	}
	old := terminal(time.Now().UTC().Add(-40 * 24 * time.Hour))
	fresh := terminal(time.Now().UTC())
	plan, err := PlanGC(f.home, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.IDs, []string{old}) {
		t.Fatalf("plan=%v want [%s]", plan.IDs, old)
	}
	// A forged plan naming a fresh record is re-validated under the lock.
	plan.IDs = append(plan.IDs, fresh)
	if err := ExecuteGC(f.home, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, "transactions", "new", "tx-"+old)); !os.IsNotExist(err) {
		t.Fatalf("expired journal kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.home, "transactions", "new", "tx-"+fresh)); err != nil {
		t.Fatalf("retained journal removed: %v", err)
	}
}

func TestExecuteGCWaitsForNoActiveTransaction(t *testing.T) {
	f := newCrashFixture(t)
	tx, err := Begin(f.home, f.target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Abort() }()
	if err := ExecuteGC(f.home, GCPlan{IDs: []string{strings.Repeat("a", 32)}}); !errors.Is(err, ErrActive) {
		t.Fatalf("GC during an active transaction error=%v, want ErrActive", err)
	}
}

func TestAbortRefusesToDiscardModifiedPreexistingFile(t *testing.T) {
	f := newCrashFixture(t)
	tx, err := Begin(f.home, f.target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "main.go"), []byte("overwritten"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Abort(); !errors.Is(err, ErrAbortModified) {
		t.Fatalf("abort error=%v, want ErrAbortModified", err)
	}
	if _, err := os.Stat(filepath.Join(tx.Workspace(), "main.go")); err != nil {
		t.Fatalf("staged tree was changed by a refused abort: %v", err)
	}
	if loaded, err := Load(f.home, tx.ID()); err != nil || loaded.Journal().Phase != Prepared {
		t.Fatalf("journal after refused abort: %v", err)
	}
}

func TestHooksMayChangePublishedTreeWithoutInvalidatingCommitRecord(t *testing.T) {
	f := newCrashFixture(t)
	tx, err := Begin(f.home, f.target)
	if err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: f.registry, Before: registryBefore, After: registryAfter}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareHooks([]HookEntry{{Kind: "shell", Command: "go mod tidy"}, {Kind: "shell", Command: "fail"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(plan); err != nil {
		t.Fatal(err)
	}
	err = tx.RunHooks(context.Background(), func(_ context.Context, h HookEntry) error {
		if h.Command == "fail" {
			return errors.New("temporary")
		}
		return os.WriteFile(filepath.Join(f.target, "go.sum"), []byte("tidy"), 0o644)
	})
	if err == nil {
		t.Fatal("mandatory hook failure was not reported")
	}
	// The first hook changed the published tree; the committed journal must
	// still load, and recovery resumes with the failed suffix only.
	calls := 0
	if err := ContinueWithHooks(context.Background(), f.home, tx.ID(), f.registry, func(context.Context, HookEntry) error { calls++; return nil }); err != nil {
		t.Fatalf("continue after tree-changing hook: %v", err)
	}
	if calls != 1 {
		t.Fatalf("resumed hook calls=%d, want 1", calls)
	}
}

func TestInProjectRelativeSymlinkIsCommittedButEscapeIsRefused(t *testing.T) {
	f := newCrashFixture(t)
	tx, err := Begin(f.home, f.target)
	if err != nil {
		t.Fatal(err)
	}
	ws := tx.Workspace()
	if err := os.MkdirAll(filepath.Join(ws, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../main.go", filepath.Join(ws, "bin", "tool")); err != nil {
		t.Fatal(err)
	}
	plan := RegistryPlan{Home: f.registry, Before: registryBefore, After: registryAfter}
	if err := tx.PrepareRegistry(plan); err != nil {
		t.Fatalf("in-project relative symlink refused: %v", err)
	}
	if err := os.Symlink("../../outside", filepath.Join(ws, "bin", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(plan); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("escaping symlink committed: %v", err)
	}
}

// prepareForContinue drives a transaction to a prepared journal with a
// complete registry plan and then drops the lock, as a process that died
// before Commit would.
func (f crashFixture) prepareForContinue(t *testing.T) *Transaction {
	t.Helper()
	tx, err := Begin(f.home, f.target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "generated.txt"), []byte("rendered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tx.PrepareRegistry(RegistryPlan{Home: f.registry, Before: registryBefore, After: registryAfter}); err != nil {
		t.Fatal(err)
	}
	tx.Release()
	return tx
}

// assertJournalKept checks that a refused recovery left the journal, the
// published target and the registry preimage in place for inspection.
func assertJournalKept(t *testing.T, f crashFixture, id string, phase Phase) {
	t.Helper()
	items, err := Inventory(f.home)
	if err != nil || len(items) != 1 || items[0].ID != id || items[0].Status != StatusActive {
		t.Fatalf("journal not kept: %+v err=%v", items, err)
	}
	tx, err := Load(f.home, id)
	if err != nil || tx.Journal().Phase != phase {
		t.Fatalf("journal phase: tx=%+v err=%v, want %s", tx, err, phase)
	}
	registry, _, _, err := state.ReadProjectsRaw(f.registry)
	if err != nil || string(registry) != string(registryBefore) {
		t.Fatalf("registry changed: %q err=%v", registry, err)
	}
}

// A prepared journal whose staged tree drifted after PrepareRegistry must be
// refused before anything moves, and must remain abortable to the before
// image.
func TestContinueFromPreparedRefusesDriftedStagingBeforePublishing(t *testing.T) {
	f := newCrashFixture(t)
	tx := f.prepareForContinue(t)
	if err := os.WriteFile(filepath.Join(tx.Workspace(), "late.txt"), []byte("late"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Continue(f.home, tx.ID(), f.registry); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Continue error=%v, want ErrUnsafe", err)
	}
	if _, err := os.Stat(tx.Workspace()); err != nil {
		t.Fatalf("staging moved by a refused Continue: %v", err)
	}
	assertJournalKept(t, f, tx.ID(), Prepared)
	recoverAndAssert(t, f)
	if _, err := os.Stat(filepath.Join(f.target, "late.txt")); !os.IsNotExist(err) {
		t.Fatalf("late file survived abort: %v", err)
	}
}

// A verification failure after Continue has published a prepared journal must
// never let abort discard the journal: the rendered files and the pending
// marker are in the target, and only an operator can resolve them.
func TestAbortRefusesAfterContinuePublishFailsVerification(t *testing.T) {
	f := newCrashFixture(t)
	tx := f.prepareForContinue(t)
	err := continueTx(f.home, tx.ID(), f.registry, func(point string) error {
		if point == "continue.after_staging_publish" {
			return os.WriteFile(filepath.Join(f.target, "late.txt"), []byte("late"), 0o644)
		}
		return nil
	})
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Continue error=%v, want ErrUnsafe", err)
	}
	if err := AbortByID(f.home, tx.ID()); err == nil {
		t.Fatal("AbortByID discarded a journal whose target was already published")
	}
	assertJournalKept(t, f, tx.ID(), Publishing)
	for _, rel := range []string{"generated.txt", "late.txt", ".tplaiter/new-transaction.pending"} {
		if _, err := os.Stat(filepath.Join(f.target, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("published evidence %s missing: %v", rel, err)
		}
	}
}

// A prepared journal whose target already carries the pending marker (for
// example a journal written by a build that published without leaving
// Prepared) is not "nothing moved": abort must keep it.
func TestAbortRefusesPreparedJournalWithPublishedTarget(t *testing.T) {
	f := newCrashFixture(t)
	tx := f.prepareForContinue(t)
	if err := os.Rename(tx.Workspace(), f.target); err != nil {
		t.Fatal(err)
	}
	if err := AbortByID(f.home, tx.ID()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("AbortByID error=%v, want ErrUnsafe", err)
	}
	assertJournalKept(t, f, tx.ID(), Prepared)
	if _, err := os.Stat(filepath.Join(f.target, "generated.txt")); err != nil {
		t.Fatalf("published file removed: %v", err)
	}
}

// A prepared journal with an unstaged target that no longer matches the
// before image is refused too, even without a marker.
func TestAbortRefusesPreparedJournalWhenTargetDiffersFromBeforeImage(t *testing.T) {
	f := newCrashFixture(t)
	err := f.runScenario(func(point string) error {
		if point == "begin.after_journal" {
			return ErrInjectedCrash
		}
		return nil
	})
	if !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("scenario error=%v", err)
	}
	if err := os.WriteFile(filepath.Join(f.target, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	items, err := Inventory(f.home)
	if err != nil || len(items) != 1 {
		t.Fatalf("inventory=%+v err=%v", items, err)
	}
	if err := AbortByID(f.home, items[0].ID); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("AbortByID error=%v, want ErrUnsafe", err)
	}
	if items, err := Inventory(f.home); err != nil || len(items) != 1 {
		t.Fatalf("journal discarded: %+v err=%v", items, err)
	}
}

const continueCrashChildEnv = "TPLAITER_NEWTX_CONTINUE_CRASH_CHILD"

// TestContinueCrashChild is the re-executed child of
// TestKilledContinueRecoversAfterPublish: it dies right after Continue's
// staging-to-target rename.
func TestContinueCrashChild(t *testing.T) {
	spec := os.Getenv(continueCrashChildEnv)
	if spec == "" {
		t.Skip("helper process for TestKilledContinueRecoversAfterPublish")
	}
	parts := strings.Split(spec, "\x1f")
	f := crashFixture{home: parts[0], target: parts[1], registry: parts[2]}
	// The transaction id is read back from the journal inventory rather than
	// passed through the environment.
	items, err := Inventory(f.home)
	if err != nil || len(items) != 1 {
		t.Fatalf("inventory=%+v err=%v", items, err)
	}
	err = continueTx(f.home, items[0].ID, f.registry, func(point string) error {
		if point == "continue.after_staging_publish" {
			os.Exit(crashExitCode)
		}
		return nil
	})
	t.Fatalf("Continue returned without reaching the failpoint: %v", err)
}

func TestKilledContinueRecoversAfterPublish(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a child process")
	}
	f := newCrashFixture(t)
	tx := f.prepareForContinue(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestContinueCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), continueCrashChildEnv+"="+strings.Join([]string{f.home, f.target, f.registry}, "\x1f"))
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != crashExitCode {
		t.Fatalf("child did not die after the rename: err=%v output=%s", err, out)
	}
	// The kill left a published target and a Publishing journal: abort must
	// refuse, and Continue must finish the publish.
	if err := AbortByID(f.home, tx.ID()); err == nil {
		t.Fatal("AbortByID discarded a journal whose target was already published")
	}
	assertJournalKept(t, f, tx.ID(), Publishing)
	recoverAndAssert(t, f)
}
