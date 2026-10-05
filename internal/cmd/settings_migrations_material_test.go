package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestSignedAnswerMigrationColdSameIDAndRefusals(t *testing.T) {
	f := nativeAnswerMigrationFixture(t, false)
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
			file.Data = bytes.ReplaceAll(file.Data, []byte("source: migration"), []byte("source: user"))
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
	assertAnswerMigrationState(t, f.projectRoot)
	for _, path := range []string{".tplaiter/migrations.json", ".tplaiter/project.yaml", "hello.txt"} {
		if !bytes.Equal(material.After[path].Data, mustMigrationFile(t, f.projectRoot, path)) {
			t.Fatalf("cold afterimage differs %s", path)
		}
	}
	if err := receipt.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared+committed cold same-ID=%s expectedFingerprint=%s material=%s ledger=%x; rehashed answer/ledger and stale-beforeimage refused", id, fingerprint, material.Fingerprint, sha256.Sum256(mustMigrationFile(t, f.projectRoot, ".tplaiter/migrations.json")))
}

func TestSignedAnswerMigrationExecutableZeroEffects(t *testing.T) {
	f := nativeAnswerMigrationFixture(t, true)
	home := filepath.Join(filepath.Dir(f.projectRoot), "exec-home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	if out, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatalf("provision %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(filepath.Dir(f.projectRoot), "source.json"), filepath.Join(filepath.Dir(f.projectRoot), "target.json")
	for path, raw := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new %v %s", err, out)
	}
	before := nativeUpdateObservedTree(t, f.projectRoot)
	out, err := executeNativeGenCLI(in, "update", "--to", f.target.Commit, "--source-input", targetPath, "--dry-run", "--json")
	if !errors.Is(err, migrations.ErrExecutionUnauthorized) {
		t.Fatalf("not a selected execution refusal: %v %s", err, out)
	}
	if !reflect.DeepEqual(before, nativeUpdateObservedTree(t, f.projectRoot)) {
		t.Fatal("selected executable refusal wrote project")
	}
	t.Log("selected signed executable migration refused before transaction; project zero effects")
}
