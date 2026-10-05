package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestNativeUpdateColdAbortCommand(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeUpdateCLIFixture(t)
	home := filepath.Join(filepath.Dir(f.projectRoot), "home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	if _, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(filepath.Dir(f.projectRoot), "source.json")
	if err := os.WriteFile(source, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", source, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new: %v %s", err, out)
	}
	r, err := composeRuntimeForProject(withInvocation(context.Background(), in), "project")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := updateplan.New(r, home, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	p, err := backend.Prepare(context.Background(), updateplan.Input{SourceInput: t5FSelection(f.source, f.sourceRefs), TargetInput: t5FSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	before := nativeGenTree(t, f.projectRoot)
	registryBefore, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	binding := r.TrustRuntime().Binding()
	tx, err := projecttransaction.BeginUpdate(context.Background(), p, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := tx.ID()
	tx.Release()
	r.Close()
	out, err := executeNativeGenCLI(in, "update", "abort", id, "--project-context", "project", "--dir", f.projectRoot, "--json")
	if err != nil {
		t.Fatalf("cold abort: %v %s", err, out)
	}
	env := decodeOne(t, out)
	if env.Operation != resultdto.OperationUpdateAbort || env.TransactionID == nil || *env.TransactionID != id || env.Project.ID != "project-t5f" {
		t.Fatalf("abort envelope: %s", out)
	}
	// Engine-owned empty control inode remains; every original file is exact.
	actual := nativeGenTree(t, f.projectRoot)
	delete(actual, ".tplaiter/update.lock")
	delete(actual, ".tplaiter/project-transactions")
	for path := range actual {
		if path == ".tplaiter/project-transactions/"+id || strings.HasPrefix(path, ".tplaiter/project-transactions/"+id+"/") {
			delete(actual, path)
		}
	}
	if !reflect.DeepEqual(before, actual) {
		t.Fatal("cold abort did not restore original project")
	}
	registryAfter, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil || !bytes.Equal(registryBefore, registryAfter) {
		t.Fatal("cold abort did not restore registry")
	}
	r, err = composeRuntimeForProject(withInvocation(context.Background(), in), "project")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !binding.Equal(r.TrustRuntime().Binding()) {
		t.Fatal("cold abort changed authority/revision")
	}
	if _, err := stateledger.VerifyStable(context.Background(), f.projectRoot, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := registeredSourceInput(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	s, err := operationtrust.DecodeSourceSelection(raw)
	if err != nil || s.Subject.Commit != f.source.Commit {
		t.Fatal("cold abort lost signed source identity")
	}
	// Cold terminal re-open is an authenticated observation before reporting success.
	if out, err := executeNativeGenCLI(in, "update", "abort", id, "--json"); err != nil {
		t.Fatalf("repeat cold abort: %v %s", err, out)
	}
	out, err = executeNativeGenCLI(in, "update", "continue", id, "--json")
	if err == nil || exitCodeFor(err) != resultdto.ExitUnavailable || out != "" {
		t.Fatalf("Continue: %v %s", err, out)
	}
}

func TestNativeUpdateMarkerScanNoFollow(t *testing.T) {
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "tplaiter-update-scan-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "edit.txt"), []byte("<<<<<<< local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	found, err := scanNativeConflictMarkers(context.Background(), root)
	if err != nil || !reflect.DeepEqual(found, []string{"edit.txt"}) {
		t.Fatalf("scan: %v %v", found, err)
	}
	if err := os.Symlink("/outside", filepath.Join(root, "foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanNativeConflictMarkers(context.Background(), root); err == nil {
		t.Fatal("scan followed symlink")
	}
}

func TestNativeUpdateSignedActionsRefuseBeforeEffects(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeUpdateCLIFixture(t, "commands:\n  build:\n    run: echo forbidden\n")
	home := filepath.Join(filepath.Dir(f.projectRoot), "home")
	t.Setenv(state.HomeEnv, home)
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	if _, err := executeNativeGenCLI(in, "trust", "provision"); err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(f.projectRoot)
	source, target := filepath.Join(base, "source.json"), filepath.Join(base, "target.json")
	for path, raw := range map[string][]byte{source: t5FSelection(f.source, f.sourceRefs), target: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := executeNativeGenCLI(in, "new", f.source.Commit, "project", "--dir", f.projectRoot, "--source-input", source, "--defaults", "--no-hooks", "--json"); err != nil {
		t.Fatalf("new: %v %s", err, out)
	}
	before := nativeUpdateObservedTree(t, f.projectRoot)
	homeBefore := nativeUpdateObservedTree(t, home)
	if out, err := executeNativeGenCLI(in, "update", "--source-input", target, "--json"); err == nil || exitCodeFor(err) != resultdto.ExitUnavailable || out != "" {
		t.Fatalf("configured action: %v %s", err, out)
	}
	if !reflect.DeepEqual(before, nativeUpdateObservedTree(t, f.projectRoot)) || !reflect.DeepEqual(homeBefore, nativeUpdateObservedTree(t, home)) {
		t.Fatal("action refusal had effects")
	}
}
