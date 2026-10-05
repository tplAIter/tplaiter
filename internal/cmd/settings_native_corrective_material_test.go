package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestNativeSettingsCorrectiveColdMaterialAndFreshPreimage(t *testing.T) {
	f := nativeSettingsFixture(t)
	home := filepath.Join(filepath.Dir(f.projectRoot), "material-home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	ctx := withInvocation(context.Background(), in)
	if _, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(filepath.Dir(f.projectRoot), "selection.json")
	if err := os.WriteFile(sourcePath, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new: %v %s", err, out)
	}
	seed := filepath.Join(f.projectRoot, "seed.sql")
	hello := filepath.Join(f.projectRoot, "hello.txt")
	mine := []byte("insert MINE\n")
	if err := os.WriteFile(seed, mine, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hello, []byte("base one\nMINE\nbase three\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := composeRuntimeForProject(ctx, "project")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	input, err := registeredSourceInput(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := updateplan.New(r, home, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	pairs := []string{"database=none", "label=beta"}
	p, err := backend.Prepare(ctx, updateplan.Input{SourceInput: input, TargetInput: input, SettingsPairs: pairs})
	if err != nil {
		t.Fatal(err)
	}
	material, _, err := p.TransactionMaterial(ctx, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), material); err != nil {
		t.Fatal(err)
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var report updateplan.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	for i := range report.Changes {
		if report.Changes[i].Warning != "" {
			report.Changes[i].Warning = "forged warning"
		}
	}
	forged := material
	forged.ExpectedFingerprint, err = bootstrap.DomainDigest(updateplan.APIVersion, report)
	if err != nil {
		t.Fatal(err)
	}
	forged.Fingerprint = ""
	forged.Fingerprint, err = bootstrap.DomainDigest("tplaiter.dev/native-update-material/v1", forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), forged); err == nil {
		t.Fatal("caller-chosen warning/fingerprint granted publication")
	}
	forged = material
	forged.After = make(map[string]updateplan.UpdateFile, len(material.After))
	for k, v := range material.After {
		forged.After[k] = v
	}
	file := forged.After["hello.txt"]
	file.Data = []byte("caller-picked conflict bytes\n")
	forged.After["hello.txt"] = file
	forged.Fingerprint = ""
	forged.Fingerprint, err = bootstrap.DomainDigest("tplaiter.dev/native-update-material/v1", forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, resolveVersion(), forged); err == nil {
		t.Fatal("caller-picked conflict bytes granted publication")
	}
	// A valid plan does not survive a local edit between preview and Begin.
	opaque, err := projecttransaction.PlanSettings(ctx, r, home, resolveVersion(), input, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seed, []byte("changed after preview\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tx, err := projecttransaction.BeginSettings(ctx, opaque, opaque.Fingerprint()); err == nil {
		tx.Release()
		t.Fatal("stale local-retention plan published")
	}
	if err := os.WriteFile(seed, mine, 0o644); err != nil {
		t.Fatal(err)
	}
	opaque, err = projecttransaction.PlanSettings(ctx, r, home, resolveVersion(), input, pairs)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := projecttransaction.BeginSettings(ctx, opaque, opaque.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	r.Close()
	// Fresh runtime cold-prepared Commit reconstructs both product decisions.
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
	if err := receipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(seed)
	if err != nil || !bytes.Equal(actual, mine) {
		t.Fatalf("cold retained seed: %v %q", err, actual)
	}
	if _, err := os.Stat(filepath.Join(f.projectRoot, "schema.sql")); !os.IsNotExist(err) {
		t.Fatalf("cold clean delete: %v", err)
	}
	actual, err = os.ReadFile(hello)
	if err != nil || !bytes.Contains(actual, []byte("<<<<<<< ours\nMINE\n=======\nbeta\n>>>>>>> template")) {
		t.Fatalf("cold marker bytes: %v %q", err, actual)
	}
	t.Logf("fresh after-lease + cold prepared commit preserved authenticated decisions; tx=%s", id)
}
