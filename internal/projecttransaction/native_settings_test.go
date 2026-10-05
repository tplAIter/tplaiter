package projecttransaction

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestNativeSettingsSealedOverridesAndColdRecovery(t *testing.T) {
	f, r, home, _ := signedUpdateCase(t, false)
	ctx := context.Background()
	source := t5DSelection(f.source, f.sourceRefs)
	pairs := []string{"label=changed"}
	plan, err := PlanSettings(ctx, r, home, "v1", source, pairs)
	if err != nil {
		t.Fatal(err)
	}
	pairs[0] = "label=untrusted-later"
	raw, err := plan.Marshal()
	if err != nil || len(raw) == 0 {
		t.Fatalf("pair clone: %v %s", err, raw)
	}
	// Tampering with a detached material cannot change the fresh same-version
	// render intent, including after cold receipt reconstruction.
	material, _, err := plan.plan.TransactionMaterial(ctx, plan.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if len(material.SettingsPairs) != 1 || material.SettingsPairs[0] != "label=changed" {
		t.Fatal("caller mutated sealed settings")
	}
	material.SettingsPairs = []string{"label=forged"}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, "v1", material); err == nil {
		t.Fatal("forged detached settings accepted")
	}
	tx, err := BeginSettings(ctx, plan, plan.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	r.Close()
	cold, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	receipt, err := OpenUpdate(ctx, cold, home, id, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	receipt.Release()
	marker, err := os.ReadFile(filepath.Join(f.project, ".tplaiter", "project.yaml"))
	if err != nil || strings.Contains(string(marker), "changed") {
		t.Fatalf("settings Abort failed: %v %s", err, marker)
	}
	plan, err = PlanSettings(ctx, cold, home, "v1", source, []string{"label=changed"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err = BeginSettings(ctx, plan, plan.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	id = tx.ID()
	tx.Release()
	cold.Close()
	cold, err = trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	receipt, err = OpenUpdate(ctx, cold, home, id, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	receipt.Release()
	marker, err = os.ReadFile(filepath.Join(f.project, ".tplaiter", "project.yaml"))
	if err != nil || !strings.Contains(string(marker), "changed") {
		t.Fatalf("settings Continue failed: %v %s", err, marker)
	}
}

func TestNativeSettingsRejectsStalePlanAndVersionOverride(t *testing.T) {
	f, r, home, _ := signedUpdateCase(t, false)
	ctx := context.Background()
	source := t5DSelection(f.source, f.sourceRefs)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := PlanSettings(cancelled, r, home, "v1", source, []string{"label=cancelled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled settings: %v", err)
	}
	backend, err := updateplan.New(r, home, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Prepare(ctx, updateplan.Input{SourceInput: source, TargetInput: t5DSelection(f.target, f.targetRefs), SettingsPairs: []string{"label=changed"}}); !errors.Is(err, updateplan.ErrSettingsInput) {
		t.Fatalf("version switching settings override: %v", err)
	}
	plan, err := PlanSettings(ctx, r, home, "v1", source, []string{"label=changed"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.project, "hello.txt")
	if err := os.WriteFile(path, []byte("local changed after preview\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tx, err := BeginSettings(ctx, plan, plan.Fingerprint()); err == nil {
		tx.Release()
		t.Fatal("stale settings plan admitted")
	}
	after, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("stale settings published registry")
	}
	if _, err := BeginSettings(ctx, &SettingsPlan{}, "forged"); !errors.Is(err, updateplan.ErrInvalid) {
		t.Fatalf("empty grant: %v", err)
	}
}
