//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// The observer only schedules interruption of real signed staging. It neither
// fabricates a phase nor changes progress or grants recovery authority.
type preparingCancelContext struct {
	context.Context
	dir     string
	minimum int
	fired   bool
}

func (c *preparingCancelContext) Err() error {
	raw, err := os.ReadFile(filepath.Join(c.dir, "state.json"))
	var record struct {
		Payload progress `json:"payload"`
	}
	if err == nil && json.Unmarshal(raw, &record) == nil && record.Payload.Phase == "preparing" && len(record.Payload.Steps) >= c.minimum {
		c.fired = true
		return context.Canceled
	}
	return c.Context.Err()
}

func interruptedPreparingUpdate(t *testing.T, minimum int) (*Transaction, *trustload.Runtime, string) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	writer := func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
		return t5DWriteNativeSourceFiles(t, root, suffix, output, extra, map[string][]byte{"!delete:hello.txt.tmpl": nil, "new/empty.txt.tmpl": {}})
	}
	f := t5DNewIntegrationFixtureWithSource(t, writer)
	ctx := context.Background()
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	bridge := updateFixtureBridge(t, f, home)
	m := bridge.material("prepare-update", nil)
	tx, err := Acquire(ctx, r, NativeUpdateKind, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tx.Release)
	material := bridge.material("after-lease", nil)
	bridge.Close()
	if err := tx.ValidateLocked(ctx, material); err != nil {
		t.Fatal(err)
	}
	if minimum < 0 {
		minimum = len(tx.expectedSteps())
	}
	boundary := &preparingCancelContext{Context: ctx, dir: tx.dir, minimum: minimum}
	if err := tx.Seal(boundary, material); !errors.Is(err, context.Canceled) || !boundary.fired {
		t.Fatalf("real staging interruption: %v fired=%v", err, boundary.fired)
	}
	if tx.state.Phase != "preparing" || len(tx.state.Steps) != minimum || tx.ID() == "" {
		t.Fatalf("wrong durable prefix: phase=%s count=%d minimum=%d", tx.state.Phase, len(tx.state.Steps), minimum)
	}
	assertUpdateBefore(t, tx, "")
	tx.Release()
	return tx, r, home
}

func TestPreparingUpdateContinuePrefixes(t *testing.T) {
	for _, minimum := range []int{0, 1, -1} {
		t.Run(strconv.Itoa(minimum), func(t *testing.T) {
			tx, r, home := interruptedPreparingUpdate(t, minimum)
			cold := coldSignedUpdate(t, r, home, tx.ID())
			defer cold.Release()
			if err := cold.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, s := range cold.state.Steps {
				if err := cold.checkStepFinal(s); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(cold.dir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := cold.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(cold.dir, "state.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("repeat changed terminal receipt")
			}
			t.Logf("real interrupted prefix %d/%d committed", len(tx.state.Steps), len(tx.expectedSteps()))
		})
	}
}

func TestPreparingUpdateOrphanRefusal(t *testing.T) {
	for _, orphan := range []string{"matching-file", "foreign-directory", "registry-slot"} {
		t.Run(orphan, func(t *testing.T) {
			tx, r, home := interruptedPreparingUpdate(t, 0)
			s := tx.expectedSteps()[0]
			s.Slot = "000000"
			_, after, _ := tx.stepFiles(s)
			name := tx.slotPath(s)
			switch orphan {
			case "matching-file":
				if err := os.WriteFile(name, after.Data, os.FileMode(after.Mode)); err != nil {
					t.Fatal(err)
				}
			case "foreign-directory":
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
			case "registry-slot":
				name = filepath.Join(tx.dir, "000999")
				if err := os.WriteFile(name, []byte("foreign registry"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			original, err := confinedLstat(name)
			if err != nil {
				t.Fatal(err)
			}
			cold := coldSignedUpdate(t, r, home, tx.ID())
			defer cold.Release()
			before, err := os.ReadFile(filepath.Join(tx.dir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := cold.Commit(context.Background()); !errors.Is(err, ErrPreparingAmbiguous) {
				t.Fatalf("orphan was adopted: %v", err)
			}
			receiptAfter, err := os.ReadFile(filepath.Join(tx.dir, "state.json"))
			if err != nil || !bytes.Equal(before, receiptAfter) {
				t.Fatal("ambiguous Continue modified receipt")
			}
			assertUpdateBefore(t, cold, "")
			if err := cold.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			actual, err := confinedLstat(name)
			if err != nil || fileID(actual) != fileID(original) || actual.Mode() != original.Mode() {
				t.Fatal("Abort removed or adopted foreign orphan")
			}
		})
	}
}

func TestPreparingUpdateCancellationAndAbort(t *testing.T) {
	tx, r, home := interruptedPreparingUpdate(t, 0)
	cold := coldSignedUpdate(t, r, home, tx.ID())
	boundary := &preparingCancelContext{Context: context.Background(), dir: cold.dir, minimum: 1}
	if err := cold.Commit(boundary); !errors.Is(err, context.Canceled) {
		t.Fatalf("Continue cancellation: %v", err)
	}
	if cold.state.Phase != "preparing" || len(cold.state.Steps) != 1 {
		t.Fatal("cancellation published preparing transaction")
	}
	assertUpdateBefore(t, cold, "")
	cold.Release()
	abort := coldSignedUpdate(t, r, home, tx.ID())
	defer abort.Release()
	if err := abort.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertUpdateBefore(t, abort, "")
}

func TestPreparingUpdatePreimageRefusal(t *testing.T) {
	tx, r, home := interruptedPreparingUpdate(t, 0)
	cold := coldSignedUpdate(t, r, home, tx.ID())
	defer cold.Release()
	name := filepath.Join(home, "projects.yaml")
	before, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, name+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cold.Commit(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("replaced registry adopted: %v", err)
	}
}

func TestPreparingUpdateMalformedNull(t *testing.T) {
	tx, r, home := interruptedPreparingUpdate(t, 0)
	// A signed null still cannot stand for an empty authenticated prefix.
	// Reopen supplies the actual key; the released object cannot sign anything.
	cold := coldSignedUpdate(t, r, home, tx.ID())
	cold.state.Steps = nil
	if err := cold.save(); err != nil {
		t.Fatal(err)
	}
	cold.Release()
	if opened, err := Open(context.Background(), r, NativeUpdateKind, home, tx.ID()); err == nil {
		opened.Release()
		t.Fatal("malformed null steps accepted")
	}
}

func TestPreparingUpdateRecordedSlotReplacement(t *testing.T) {
	tx, r, home := interruptedPreparingUpdate(t, 1)
	s := tx.state.Steps[0]
	name := tx.slotPath(s)
	_, after, _ := tx.stepFiles(s)
	retained := name + ".retained"
	if err := os.Rename(name, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, after.Data, os.FileMode(after.Mode)); err != nil {
		t.Fatal(err)
	}
	cold := coldSignedUpdate(t, r, home, tx.ID())
	defer cold.Release()
	before := cold.state
	if err := cold.Commit(context.Background()); !errors.Is(err, ErrPreparingAmbiguous) {
		t.Fatalf("replaced inode adopted: %v", err)
	}
	if !reflect.DeepEqual(before, cold.state) {
		t.Fatal("refusal changed preparing state")
	}
}
