//go:build darwin || linux

package runtimeassembly_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type publicHome struct{}

func (publicHome) DigestSecret(context.Context, stateledger.SecretLocator) (stateledger.SecretDigestResult, error) {
	return stateledger.SecretDigestResult{}, nil
}

func TestConcreteTerminalAndPreparedMigration(t *testing.T) {
	ctx := context.Background()
	r, home, root := nativeSignedProject(t)
	opts := runtimeassembly.Options{Home: home, SecretProvider: publicHome{}}
	plan, err := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget"}})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := projecttransaction.BeginNative(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	tx.Release() // actual retained prepared receipt, not a fake journal label
	before, err := os.ReadFile(filepath.Join(root, stateledger.StateDir, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	saved := capture(t, r.ProjectContext().RootPath, home)
	_, err = runtimeassembly.VerifyReadOnly(ctx, r, opts)
	unchanged(t, saved, r.ProjectContext().RootPath, home)
	var journal *runtimeassembly.JournalError
	if !errors.As(err, &journal) || journal.Status != inventory.StatusActive {
		t.Fatalf("prepared: %v", err)
	}
	_, err = runtimeassembly.ApplyPlan(ctx, r, opts, "unused")
	if !errors.As(err, &journal) || journal.Status != inventory.StatusActive {
		t.Fatalf("prepared apply: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, stateledger.StateDir, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("refusal changed marker")
	}
	recovered, err := projecttransaction.OpenNative(ctx, r, home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Commit(ctx); err != nil {
		recovered.Release()
		t.Fatal(err)
	}
	recovered.Release()
	observed, err := runtimeassembly.VerifyReadOnly(ctx, r, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Journals) != 1 || !observed.Journals[0].Terminal() {
		t.Fatal("terminal history not retained")
	}
	next, err := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: "entity", Name: "Gadget"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := projecttransaction.BeginNative(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Commit(ctx); err != nil {
		second.Release()
		t.Fatal(err)
	}
	second.Release()
	if _, err := runtimeassembly.Load(ctx, r, opts); err != nil {
		t.Fatal(err)
	}
	noop, err := stateledger.Plan(root, stateledger.Options{HomeRoot: home, SecretProvider: publicHome{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeassembly.ApplyPlan(ctx, r, opts, noop.PlanSHA256); err != nil {
		t.Fatal(err)
	}
}

func TestConcreteLegacyMarkerMigration(t *testing.T) {
	ctx := context.Background()
	r, home, root := nativeSignedProject(t)
	marker := filepath.Join(root, stateledger.StateDir, "project.yaml")
	legacy := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: project-local-go\ntemplate:\n  repo: https://github.com/tplAIter/template-go\n  name: go\n  version: " + publicGoCommit + "\nproject: {}\nsettings: {}\nruntime: {}\n")
	if err := os.WriteFile(marker, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	// Establish the same persistent coordination inode before the reviewed plan;
	// the adapter refuses a stale digest if a previously absent lock changes it.
	if err := os.WriteFile(filepath.Join(root, stateledger.StateDir, "update.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := runtimeassembly.Options{Home: home, SecretProvider: publicHome{}}
	planned, err := runtimeassembly.Plan(ctx, r, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.Mutations) != 1 || planned.From != stateledger.ProjectV1 {
		t.Fatal("not a real marker migration")
	}
	if _, err := runtimeassembly.ApplyPlan(ctx, r, opts, planned.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeassembly.VerifyReadOnly(ctx, r, opts); err != nil {
		t.Fatal(err)
	}
}

func TestConcreteJournalDiagnosticsAndUncovered(t *testing.T) {
	ctx := context.Background()
	r, home, _ := nativeSignedProject(t)
	plan, err := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: "entity", Name: "Widget"}})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := projecttransaction.BeginNative(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		tx.Release()
		t.Fatal(err)
	}
	tx.Release()
	opts := runtimeassembly.Options{Home: home, SecretProvider: publicHome{}}
	journalDir := filepath.Join(home, "transactions/project/tx-"+tx.ID())
	path := filepath.Join(journalDir, "plan.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Change the envelope version, not an arbitrary caller status.
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, ok := envelope["payload"].(map[string]any)
	if !ok {
		t.Fatal("missing actual payload")
	}
	payload["apiVersion"] = "tplaiter.dev/project-transaction/v99"
	future, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, future, 0o600); err != nil {
		t.Fatal(err)
	}
	{
		saved := capture(t, r.ProjectContext().RootPath, home)
		_, err = runtimeassembly.VerifyReadOnly(ctx, r, opts)
		unchanged(t, saved, r.ProjectContext().RootPath, home)
	}
	var failure *runtimeassembly.JournalError
	if !errors.As(err, &failure) || failure.Status != inventory.StatusFuture {
		t.Fatalf("future: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(journalDir, "state.json")
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	{
		saved := capture(t, r.ProjectContext().RootPath, home)
		_, err = runtimeassembly.VerifyReadOnly(ctx, r, opts)
		unchanged(t, saved, r.ProjectContext().RootPath, home)
	}
	if !errors.As(err, &failure) || failure.Status != inventory.StatusUnsafe {
		t.Fatalf("unsafe: %v", err)
	}
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	other, _, _ := nativeSignedProject(t)
	{
		saved := capture(t, other.ProjectContext().RootPath, home)
		_, err = runtimeassembly.VerifyReadOnly(ctx, other, opts)
		unchanged(t, saved, other.ProjectContext().RootPath, home)
	}
	if !errors.As(err, &failure) || failure.Status != inventory.StatusUnresolved {
		t.Fatalf("uncovered: %v", err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(r.ProjectContext().RootPath, stateledger.StateDir, stateledger.RootLockFile))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := provenance.DecodeRootTemplateLock(lockRaw)
	if err != nil {
		t.Fatal(err)
	}
	selectionRaw, err := os.ReadFile(filepath.Join(home, "fixture-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(selectionRaw, &selection); err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, selection)
	if err != nil {
		t.Fatal(err)
	}
	leaf := strings.TrimPrefix(lock.Root.StatementCAS, "sha256:")
	sourceCAS := filepath.Join(loaded.Install.EvidenceRoot, "sha256", leaf[:2], leaf[2:])
	sourceBytes, err := os.ReadFile(sourceCAS)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sourceCAS); err != nil {
		t.Fatal(err)
	}
	{
		saved := capture(t, r.ProjectContext().RootPath, home)
		_, err = runtimeassembly.VerifyReadOnly(ctx, r, opts)
		unchanged(t, saved, r.ProjectContext().RootPath, home)
	}
	if !errors.As(err, &failure) || failure.Status != inventory.StatusMissingCAS {
		t.Fatalf("missingCAS: %v", err)
	}
	if err := os.WriteFile(sourceCAS, sourceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

type image struct {
	info os.FileInfo
	hash [32]byte
}

func capture(t *testing.T, roots ...string) map[string]image {
	t.Helper()
	out := map[string]image{}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(name string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(name)
			if err != nil {
				return err
			}
			value := image{info: info}
			if info.Mode().IsRegular() {
				raw, err := os.ReadFile(name)
				if err != nil {
					return err
				}
				value.hash = sha256.Sum256(raw)
			}
			out[name] = value
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func unchanged(t *testing.T, before map[string]image, roots ...string) {
	t.Helper()
	after := capture(t, roots...)
	if len(after) != len(before) {
		t.Fatal("refusal changed paths")
	}
	for name, old := range before {
		now, ok := after[name]
		if !ok || !os.SameFile(old.info, now.info) || old.info.Mode() != now.info.Mode() || old.hash != now.hash {
			t.Fatal("refusal changed bytes/mode/inode")
		}
	}
}
