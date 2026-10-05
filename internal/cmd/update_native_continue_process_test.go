package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

// Observing a synthetic receipt only schedules cancellation; it never grants
// recovery authority or rewrites signed journal bytes. The facade stages and
// seals every interrupted prefix itself.
type nativeUpdateBoundaryCancel struct {
	context.Context
	home, phase string
	minimum     int
	fired       bool
}

func (c *nativeUpdateBoundaryCancel) Err() error {
	names, _ := filepath.Glob(filepath.Join(c.home, "transactions", "project", "tx-*", "state.json"))
	for _, name := range names {
		raw, err := os.ReadFile(name)
		var doc struct {
			Payload struct {
				Phase string            `json:"phase"`
				Steps []json.RawMessage `json:"steps"`
			} `json:"payload"`
		}
		if err == nil && json.Unmarshal(raw, &doc) == nil && doc.Payload.Phase == c.phase && len(doc.Payload.Steps) >= c.minimum {
			c.fired = true
			return context.Canceled
		}
	}
	return c.Context.Err()
}

func TestNativeUpdateInstalledColdContinueAndSharedHome(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeUpdateCLIFixtureWithDirectories(t, true)
	base := filepath.Dir(f.projectRoot)
	home := filepath.Join(base, "continue-home")
	ledgerHome := filepath.Join(home, "tplaiter")
	var install trustload.RuntimeInstall
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{"project": f.projectRoot}
	for _, key := range []string{"applying", "committed", "preparing-first", "preparing-second", "cancel"} {
		pc := install.ProjectContexts[0]
		pc.Key, pc.ProjectID, pc.RootPath = key, "project-"+key, filepath.Join(base, key)
		roots[key] = pc.RootPath
		install.ProjectContexts = append(install.ProjectContexts, pc)
	}
	raw = t5FJSON(t, install)
	if err := os.WriteFile(f.selection.RuntimeConfig.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f.selection.RuntimeConfig.SHA256, err = install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "project"}
	raw = t5FJSON(t, registration)
	registrationPath := filepath.Join(base, "registration.json")
	if err := os.WriteFile(registrationPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	bin := filepath.Join(base, "tplaiter")
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir, build.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		child := exec.CommandContext(ctx, bin, args...)
		child.Env, child.Dir = testProcessEnv(home), base
		return child.Output()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	sourcePath, targetPath := filepath.Join(base, "source.json"), filepath.Join(base, "target.json")
	for name, data := range map[string][]byte{sourcePath: t5FSelection(f.source, f.sourceRefs), targetPath: t5FSelection(f.target, f.targetRefs)} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(state.HomeEnv, ledgerHome)
	observed := func() map[string]string {
		result := map[string]string{}
		for key, root := range roots {
			for p, value := range nativeUpdateObservedTree(t, root) {
				result[key+"/"+p] = value
			}
		}
		for prefix, root := range map[string]string{"home": ledgerHome, "objects": install.ObjectOrigins[0].RootPath, "evidence": install.EvidenceRoot} {
			for p, value := range nativeUpdateObservedTree(t, root) {
				result[prefix+"/"+p] = value
			}
		}
		return result
	}
	for _, key := range []string{"project", "applying", "committed", "preparing-first", "preparing-second", "cancel"} {
		if out, err := run("new", f.source.Commit, "project", "--project-context", key, "--dir", roots[key], "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
			t.Fatalf("new %s: %v %s", key, err, out)
		}
		if err := os.WriteFile(filepath.Join(roots[key], "hello.txt"), []byte("local one\nbase two\nbase three\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	begin := func(t *testing.T, key string, stageCtx context.Context) (string, error) {
		t.Helper()
		in := invocation{Selection: f.selection, ProjectKey: key, Clock: f.clock}
		r, err := composeRuntimeForProject(withInvocation(context.WithoutCancel(stageCtx), in), key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		b, err := updateplan.New(r, ledgerHome, resolveVersion())
		if err != nil {
			t.Fatal(err)
		}
		p, err := b.Prepare(context.WithoutCancel(stageCtx), updateplan.Input{SourceInput: t5FSelection(f.source, f.sourceRefs), TargetInput: t5FSelection(f.target, f.targetRefs)})
		if err != nil {
			t.Fatal(err)
		}
		tx, err := projecttransaction.BeginUpdate(stageCtx, p, p.Fingerprint())
		if tx == nil {
			t.Fatalf("begin has no retained handle: %v", err)
		}
		defer tx.Release()
		if err == nil && key == "applying" {
			err = tx.Apply(stageCtx)
		}
		return tx.ID(), err
	}
	requireFailure := func(t *testing.T, label, id string, code resultdto.ExitCode, diagnostic string, extra ...string) {
		t.Helper()
		before := observed()
		args := append([]string{"update", "continue", id, "--project-context", "project", "--dir", roots["project"], "--json"}, extra...)
		out, err := run(args...)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != int(code) {
			t.Fatalf("%s exit: %v %s", label, err, out)
		}
		env := decodeOne(t, string(out))
		if env.Operation != resultdto.OperationUpdateContinue || env.Status != resultdto.StatusBlocked && env.Status != resultdto.StatusFailed || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != diagnostic || env.Project != nil || env.TransactionID != nil || len(env.Changes) != 0 {
			t.Fatalf("%s refusal: %s", label, out)
		}
		if !reflect.DeepEqual(before, observed()) {
			t.Fatalf("%s refusal changed project/home/CAS/receipt", label)
		}
		t.Logf("%s: %s", label, out)
	}
	assertPublished := func(t *testing.T, key string) {
		t.Helper()
		root := roots[key]
		raw, err := os.ReadFile(filepath.Join(root, "hello.txt"))
		if err != nil || string(raw) != "local one\nbase two\nupstream three\n" {
			t.Fatalf("%s three-way: %v %q", key, err, raw)
		}
		if _, err := os.Stat(filepath.Join(root, "obsolete.txt")); !os.IsNotExist(err) {
			t.Fatalf("%s deletion: %v", key, err)
		}
		if raw, err := os.ReadFile(filepath.Join(root, "added.txt")); err != nil || string(raw) != "new owned\n" {
			t.Fatalf("%s addition: %v %q", key, err, raw)
		}
		raw, err = os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		projects, err := state.DecodeProjectsRaw(raw)
		if err != nil {
			t.Fatal(err)
		}
		pc := install.ProjectContexts[0]
		for _, candidate := range install.ProjectContexts {
			if candidate.Key == key {
				pc = candidate
			}
		}
		entry, found := projects.FindByID(pc.ProjectID)
		if !found || entry.Path != root || entry.Template.Version != f.target.Commit {
			t.Fatalf("%s registry: %+v", key, entry)
		}
		in := invocation{Selection: f.selection, ProjectKey: key, Clock: f.clock}
		r, err := composeRuntimeForProject(withInvocation(context.Background(), in), key)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := stateledger.VerifyStable(context.Background(), root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
			t.Fatal(err)
		}
		input, err := registeredSourceInput(context.Background(), r)
		if err != nil || !strings.Contains(string(input), f.target.Commit) {
			t.Fatalf("%s cold source: %v %s", key, err, input)
		}
	}
	firstID, err := begin(t, "project", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireFailure(t, "foreign context", firstID, resultdto.ExitTransaction, "TPL-E-NATIVE-UPDATE-TRANSACTION", "--project-context", "applying", "--dir", roots["applying"])
	requireFailure(t, "unknown context", firstID, resultdto.ExitUnavailable, "TRUST_PROVENANCE_UNAVAILABLE", "--project-context", "missing")
	requireFailure(t, "wrong root", firstID, resultdto.ExitTrust, "TRUST_PROJECT_CONTEXT_MISMATCH", "--dir", base)
	requireFailure(t, "wrong id", strings.Repeat("f", 32), resultdto.ExitTransaction, "TPL-E-NATIVE-UPDATE-TRANSACTION")
	receipt := filepath.Join(ledgerHome, "transactions", "project", "tx-"+firstID, "state.json")
	original, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt, append(append([]byte{}, original...), '!'), 0o600); err != nil {
		t.Fatal(err)
	}
	requireFailure(t, "tampered receipt", firstID, resultdto.ExitTransaction, "TPL-E-NATIVE-UPDATE-TRANSACTION")
	if err := os.WriteFile(receipt, original, 0o600); err != nil {
		t.Fatal(err)
	}
	foreignRoot := roots["project"]
	savedRoot := foreignRoot + ".saved"
	if err := os.Rename(foreignRoot, savedRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(foreignRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	savedTree := nativeUpdateObservedTree(t, savedRoot)
	requireFailure(t, "foreign root identity", firstID, resultdto.ExitTransaction, "TPL-E-NATIVE-UPDATE-TRANSACTION")
	if !reflect.DeepEqual(savedTree, nativeUpdateObservedTree(t, savedRoot)) {
		t.Fatal("foreign root refusal changed retained original")
	}
	if err := os.Remove(foreignRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedRoot, foreignRoot); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"project", "applying", "committed"} {
		t.Run(key, func(t *testing.T) {
			firstTree := nativeUpdateObservedTree(t, roots["project"])
			id := firstID
			if key == "applying" {
				var err error
				id, err = begin(t, key, context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}
			if key == "committed" {
				out, err := run("update", "--project-context", key, "--dir", roots[key], "--source-input", targetPath, "--json")
				if err != nil {
					t.Fatalf("actual CLI A->B: %v %s", err, out)
				}
				env := decodeOne(t, string(out))
				if env.TransactionID == nil {
					t.Fatal("missing apply receipt")
				}
				id = *env.TransactionID
			}
			for retry := 0; retry < 2; retry++ {
				before := observed()
				out, err := run("update", "continue", id, "--project-context", key, "--dir", roots[key], "--json")
				if err != nil {
					t.Fatalf("Continue %s: %v %s", key, err, out)
				}
				env := decodeOne(t, string(out))
				if env.Operation != resultdto.OperationUpdateContinue || env.Status != resultdto.StatusOK || env.TransactionID == nil || *env.TransactionID != id || env.Project == nil || env.Project.ID != "project-"+key && key != "project" {
					t.Fatalf("Continue envelope: %s", out)
				}
				assertPublished(t, key)
				if (retry != 0 || key == "committed") && !reflect.DeepEqual(before, observed()) {
					t.Fatal("terminal confirmation changed inventory")
				}
				t.Logf("cold %s retry%d: %s", key, retry, out)
			}
			out, err := run("update", "--project-context", key, "--dir", roots[key], "--source-input", targetPath, "--json")
			if err != nil {
				t.Fatalf("actual CLI B->B: %v %s", err, out)
			}
			env := decodeOne(t, string(out))
			if env.Status != resultdto.StatusOK || env.TransactionID == nil {
				t.Fatalf("B->B: %s", out)
			}
			before := observed()
			if out, err := run("update", "continue", *env.TransactionID, "--project-context", key, "--dir", roots[key], "--json"); err != nil {
				t.Fatalf("no-op cold confirmation: %v %s", err, out)
			}
			if !reflect.DeepEqual(before, observed()) {
				t.Fatal("no-op terminal confirmation had effects")
			}
			if key != "project" && !reflect.DeepEqual(firstTree, nativeUpdateObservedTree(t, roots["project"])) {
				t.Fatal("shared-home publication changed first project")
			}
		})
	}
	publication := func(root string) map[string]string {
		m := nativeUpdateObservedTree(t, root)
		for path := range m {
			if path == ".tplaiter/update.lock" || path == ".tplaiter/project-transactions" || strings.HasPrefix(path, ".tplaiter/project-transactions/") {
				delete(m, path)
			}
		}
		return m
	}
	for _, tc := range []struct {
		key            string
		minimum, steps int
	}{{"preparing-first", 0, 7}, {"preparing-second", 8, 10}} {
		t.Run(tc.key, func(t *testing.T) {
			originalProject := publication(roots[tc.key])
			originalRegistry, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			boundary := &nativeUpdateBoundaryCancel{Context: context.Background(), home: ledgerHome, phase: "preparing", minimum: tc.minimum}
			id, err := begin(t, tc.key, boundary)
			if !errors.Is(err, context.Canceled) || !boundary.fired || id == "" {
				t.Fatalf("genuine staging prefix: %s %v fired=%v", id, err, boundary.fired)
			}
			receiptRaw, err := os.ReadFile(filepath.Join(ledgerHome, "transactions", "project", "tx-"+id, "state.json"))
			var record struct {
				Payload struct {
					Phase string            `json:"phase"`
					Steps []json.RawMessage `json:"steps"`
				} `json:"payload"`
			}
			if err != nil || json.Unmarshal(receiptRaw, &record) != nil || record.Payload.Phase != "preparing" || len(record.Payload.Steps) != tc.steps {
				t.Fatalf("genuine preparing counter: %v %s", err, receiptRaw)
			}
			t.Logf("genuine signed preparing prefix: steps=%d", len(record.Payload.Steps))
			requireFailure(t, tc.key, id, resultdto.ExitUnavailable, "TRUST_NATIVE_UPDATE_CONTINUE_UNSUPPORTED", "--project-context", tc.key, "--dir", roots[tc.key])
			registry, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
			if err != nil || !bytes.Equal(originalRegistry, registry) || !reflect.DeepEqual(originalProject, publication(roots[tc.key])) {
				t.Fatal("preparing prefix published project or registry")
			}
			if out, err := run("update", "abort", id, "--project-context", tc.key, "--dir", roots[tc.key], "--json"); err != nil {
				t.Fatalf("preparing Abort: %v %s", err, out)
			}
		})
	}
	t.Run("cancelled applying", func(t *testing.T) {
		id, err := begin(t, "cancel", context.Background())
		if err != nil {
			t.Fatal(err)
		}
		originalProject := publication(roots["cancel"])
		originalRegistry, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		boundary := &nativeUpdateBoundaryCancel{Context: context.Background(), home: ledgerHome, phase: "applying"}
		in := invocation{Selection: f.selection, ProjectKey: "cancel", Clock: f.clock}
		cmd := newTrustRootCommand(in)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"update", "continue", id, "--project-context", "cancel", "--dir", roots["cancel"], "--json"})
		err = cmd.ExecuteContext(withInvocation(boundary, in))
		if err == nil || exitCodeFor(err) != resultdto.ExitTransaction || !errors.Is(err, context.Canceled) || !boundary.fired {
			t.Fatalf("cancel classification: %v fired=%v %s", err, boundary.fired, out.String())
		}
		registry, readErr := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
		if readErr != nil || !bytes.Equal(originalRegistry, registry) || !reflect.DeepEqual(originalProject, publication(roots["cancel"])) {
			t.Fatal("cancelled Continue failed conditional restoration")
		}
		t.Logf("cancellation remains transaction failure: %v", err)
		// Together with committed above, these are two distinct installed CLI
		// Apply admissions (A->B then B->B) in the same sealed registry home.
		firstTree := nativeUpdateObservedTree(t, roots["committed"])
		for _, expected := range []struct {
			ref    string
			status resultdto.Status
		}{{f.source.Commit, resultdto.StatusChanges}, {f.target.Commit, resultdto.StatusOK}} {
			out, err := run("update", "--project-context", "cancel", "--dir", roots["cancel"], "--source-input", targetPath, "--json")
			if err != nil {
				t.Fatalf("shared-home installed Apply: %v %s", err, out)
			}
			env := decodeOne(t, string(out))
			if env.Operation != resultdto.OperationUpdateApply || env.Status != expected.status || env.CurrentRef != expected.ref || env.TargetRef != f.target.Commit || env.Project == nil || env.Project.ID != "project-cancel" || env.TransactionID == nil {
				t.Fatalf("shared-home signed Apply: %s", out)
			}
			assertPublished(t, "cancel")
			t.Logf("second installed CLI context shared-home Apply: %s", out)
			before := observed()
			if out, err := run("update", "continue", *env.TransactionID, "--project-context", "cancel", "--dir", roots["cancel"], "--json"); err != nil {
				t.Fatalf("shared-home terminal confirmation: %v %s", err, out)
			}
			if !reflect.DeepEqual(before, observed()) || !reflect.DeepEqual(firstTree, nativeUpdateObservedTree(t, roots["committed"])) {
				t.Fatal("shared-home terminal confirmation changed inventory or first CLI project")
			}
		}
	})
}
