package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestDeprecatedColdSameIDAndRefusals(t *testing.T) {
	f := nativeDeprecatedFixture(t)
	home := filepath.Join(filepath.Dir(f.projectRoot), "material-home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	ctx := withInvocation(context.Background(), in)
	if out, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatalf("provision %v %s", err, out)
	}
	sourcePath := filepath.Join(filepath.Dir(f.projectRoot), "source.json")
	if err := os.WriteFile(sourcePath, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new %v %s", err, out)
	}
	r, err := composeRuntimeForProject(ctx, "project")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	source, err := registeredSourceInput(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := updateplan.New(r, home, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	before := nativeUpdateObservedTree(t, f.projectRoot)
	plan, err := backend.Prepare(ctx, updateplan.Input{SourceInput: source, TargetInput: t5FSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	material, _, err := plan.TransactionMaterial(ctx, plan.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, nativeUpdateObservedTree(t, f.projectRoot)) {
		t.Fatal("prepare/material wrote project")
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), material); err != nil {
		t.Fatal(err)
	}

	raw, err := plan.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var report updateplan.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Deprecations) < 4 {
		t.Fatal("diagnostics not fingerprinted")
	}
	report.Deprecations = []string{"caller-picked reference"}
	forgedReport := material
	forgedReport.ExpectedFingerprint, err = bootstrap.DomainDigest(updateplan.APIVersion, report)
	if err != nil {
		t.Fatal(err)
	}
	forgedReport.Fingerprint = ""
	forgedReport.Fingerprint, err = bootstrap.DomainDigest("tplaiter.dev/native-update-material/v1", forgedReport)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), forgedReport); err == nil {
		t.Fatal("rehashed deprecation diagnostics admitted")
	}
	// The caller can recompute a public transport fingerprint but cannot replace
	// either ledger or answer afterimages with another signed-source computation.
	for _, path := range []string{".tplaiter/migrations.json", ".tplaiter/project.yaml"} {
		forged := material
		forged.After = make(map[string]updateplan.UpdateFile, len(material.After))
		for k, v := range material.After {
			forged.After[k] = v
		}
		file := forged.After[path]
		if path == ".tplaiter/migrations.json" {
			file.Data = []byte(`{"version":1,"applied":[]}`)
		} else {
			file.Data = bytes.ReplaceAll(file.Data, []byte("source: default"), []byte("source: user"))
		}
		forged.After[path] = file
		forged.Fingerprint = ""
		forged.Fingerprint, err = bootstrap.DomainDigest("tplaiter.dev/native-update-material/v1", forged)
		if err != nil {
			t.Fatal(err)
		}
		if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), forged); err == nil {
			t.Fatalf("rehashed tampered %s admitted", path)
		}
	}
	hello := filepath.Join(f.projectRoot, "hello.txt")
	original := mustMigrationFile(t, f.projectRoot, "hello.txt")
	if err := os.WriteFile(hello, []byte("stale local edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tx, err := projecttransaction.BeginUpdate(ctx, plan, plan.Fingerprint()); err == nil {
		tx.Release()
		t.Fatal("stale plan admitted")
	}
	if err := os.WriteFile(hello, original, 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err = backend.Prepare(ctx, updateplan.Input{SourceInput: source, TargetInput: t5FSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := plan.Fingerprint()
	tx, err := projecttransaction.BeginUpdate(ctx, plan, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	r.Close()
	cold, err := composeRuntimeForProject(ctx, "project")
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	receipt, err := projecttransaction.OpenUpdate(ctx, cold, home, id, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	defer receipt.Release()
	if receipt.ID() != id {
		t.Fatal("cold receipt changed ID")
	}
	if err := receipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeprecatedState(t, f.projectRoot)
	for _, path := range []string{".tplaiter/migrations.json", ".tplaiter/project.yaml", "hello.txt"} {
		if !bytes.Equal(material.After[path].Data, mustMigrationFile(t, f.projectRoot, path)) {
			t.Fatalf("cold afterimage differs %s", path)
		}
	}
	if err := receipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared+committed cold same-ID=%s expectedFingerprint=%s material=%s ledger=%x; rehashed answer/ledger and stale-beforeimage refused", id, fingerprint, material.Fingerprint, sha256.Sum256(mustMigrationFile(t, f.projectRoot, ".tplaiter/migrations.json")))
	receipt.Release()
	input, err := registeredSourceInput(ctx, cold)
	if err != nil {
		t.Fatal(err)
	}
	settingsPlan, err := projecttransaction.PlanSettings(ctx, cold, home, resolveVersion(), input, []string{"choice=old"})
	if err != nil {
		t.Fatal(err)
	}
	settingsFP := settingsPlan.Fingerprint()
	settingsTX, err := projecttransaction.BeginSettings(ctx, settingsPlan, settingsFP)
	if err != nil {
		t.Fatal(err)
	}
	settingsID := settingsTX.ID()
	settingsTX.Release()
	cold.Close()
	again, err := composeRuntimeForProject(ctx, "project")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	settingsReceipt, err := projecttransaction.OpenUpdate(ctx, again, home, settingsID, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	defer settingsReceipt.Release()
	if settingsReceipt.ID() != settingsID {
		t.Fatal("settings cold ID changed")
	}
	if err := settingsReceipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeprecatedOrigin(t, f.projectRoot, "choice", "user")
	if err := settingsReceipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded retired same-value cold settings txn=%s fingerprint=%s marker=%x", settingsID, settingsFP, sha256.Sum256(mustMigrationFile(t, f.projectRoot, ".tplaiter/project.yaml")))
}
