//go:build darwin || linux

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type nativeVerifyImage struct {
	info   os.FileInfo
	digest [32]byte
}

func nativeVerifySnapshot(t *testing.T, roots ...string) map[string]nativeVerifyImage {
	t.Helper()
	out := map[string]nativeVerifyImage{}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			image := nativeVerifyImage{info: info}
			if info.Mode().IsRegular() {
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				image.digest = sha256.Sum256(raw)
			}
			out[path] = image
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func nativeVerifyUnchanged(t *testing.T, before map[string]nativeVerifyImage, roots ...string) {
	t.Helper()
	after := nativeVerifySnapshot(t, roots...)
	if len(after) != len(before) {
		t.Fatal("readonly verify changed paths")
	}
	for path, old := range before {
		now, ok := after[path]
		if !ok || !os.SameFile(old.info, now.info) || old.info.Mode() != now.info.Mode() || old.digest != now.digest {
			t.Fatalf("readonly verify changed bytes/mode/inode at %s", path)
		}
	}
}

func nativeVerifyCLI(t *testing.T, in invocation, root, home, code string, exit resultdto.ExitCode) {
	t.Helper()
	before := nativeVerifySnapshot(t, root, home)
	c := newTrustRootCommand(in)
	var stdout, stderr bytes.Buffer
	c.SetOut(&stdout)
	actualExit := runMain(c, []string{"verify", "--project-context=project", "--dir", root, "--json"}, &stderr)
	out := stdout.String()
	env := decodeOne(t, out)
	if code == "" {
		if actualExit != resultdto.ExitSuccess.Int() || env.Status != resultdto.StatusOK {
			t.Fatalf("verify success: exit=%d %s", actualExit, out)
		}
	} else {
		validDiagnostics := len(env.Diagnostics) == 1 && env.Diagnostics[0].Code == code
		if code == projectverify.TrustCode && len(env.Diagnostics) == 2 && env.Diagnostics[0].Code == code && env.Diagnostics[1].Code == "TRUST_RUNTIME_INVALID" {
			validDiagnostics = true
		}
		if actualExit != exit.Int() || !validDiagnostics {
			t.Fatalf("verify %s: exit=%d %s", code, actualExit, out)
		}
		if len(env.Data) != 0 || env.Project != nil {
			t.Fatal("refusal published a verified project")
		}
	}
	nativeVerifyUnchanged(t, before, root, home)
}

func TestNativeVerifyCLIConcreteJournalReadiness(t *testing.T) {
	in, root := installedNativeGenCLI(t)
	home := os.Getenv(state.HomeEnv)
	ctx := withInvocation(context.Background(), in)
	r, err := composeRuntimeForProject(ctx, "project")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	nativeVerifyCLI(t, in, root, home, "", resultdto.ExitSuccess) // no native journals, no lock creation
	plan, err := gen.PlanNative(ctx, r, home, []gen.NativeOperation{{Kind: "note", Name: "FirstNote", Provided: map[string]string{"label": "one"}}})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := projecttransaction.BeginNative(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, projectverify.TransactionCode, resultdto.ExitTransaction) // real live writer lock
	tx.Release()
	nativeVerifyCLI(t, in, root, home, projectverify.TransactionCode, resultdto.ExitTransaction) // durable prepared, no live writer
	resumed, err := projecttransaction.OpenNative(ctx, r, home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.Commit(ctx); err != nil {
		resumed.Release()
		t.Fatal(err)
	}
	resumed.Release()
	nativeVerifyCLI(t, in, root, home, "", resultdto.ExitSuccess)
	if out, err := executeNativeGenCLI(in, "gen", "note", "SecondNote", "--label=two", "--no-build", "--json"); err != nil {
		t.Fatalf("next genuine gen: %v %s", err, out)
	}
	nativeVerifyCLI(t, in, root, home, "", resultdto.ExitSuccess)
	journal := filepath.Join(home, "transactions/project/tx-"+tx.ID(), "state.json")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(before, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, ok := envelope["payload"].(map[string]any)
	if !ok {
		t.Fatal("missing envelope payload")
	}
	payload["apiVersion"] = "tplaiter.dev/project-transaction/v99"
	future, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, future, 0o600); err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, projectverify.TransactionCode, resultdto.ExitTransaction)
	if err := os.WriteFile(journal, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, projectverify.StateCode, resultdto.ExitOperational)
	if err := os.WriteFile(journal, before, 0o600); err != nil {
		t.Fatal(err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(root, stateledger.StateDir, stateledger.RootLockFile))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := provenance.DecodeRootTemplateLock(lockRaw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := trustload.Load(ctx, in.Selection)
	if err != nil {
		t.Fatal(err)
	}
	leaf := lock.Root.StatementCAS[len("sha256:"):]
	cas := filepath.Join(loaded.Install.EvidenceRoot, "sha256", leaf[:2], leaf[2:])
	evidence, err := os.ReadFile(cas)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cas); err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, projectverify.OfflineMissCode, resultdto.ExitUnavailable)
	if err := os.WriteFile(cas, evidence, 0o600); err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, "", resultdto.ExitSuccess)
	// The native route retains the existing current-marker trust diagnostic.
	markerPath := filepath.Join(root, stateledger.StateDir, "project.yaml")
	markerBytes, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(markerBytes, &marker); err != nil {
		t.Fatal(err)
	}
	marker.ID = "foreign-project"
	foreignMarker, err := yaml.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, foreignMarker, 0o644); err != nil {
		t.Fatal(err)
	}
	nativeVerifyCLI(t, in, root, home, projectverify.TrustCode, resultdto.ExitTrust)
	if err := os.WriteFile(markerPath, markerBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	// Explicit runtime mismatches, including a CAS wrapper, must not downgrade.
	_, err = projectverify.Verify(ctx, root, r.TrustRuntime(), projectverify.Options{Runtime: r, CAS: wrappedNativeCAS{r}, HomeRoot: home, SecretProvider: readonlyHomeClassifier{}})
	var diagnostic *resultdto.DiagnosticError
	if !errors.As(err, &diagnostic) || diagnostic.Value.Code != projectverify.TrustCode {
		t.Fatalf("CAS downgrade: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = projectverify.Verify(ctx, root, r.TrustRuntime(), projectverify.Options{Runtime: r, CAS: r, HomeRoot: home, SecretProvider: readonlyHomeClassifier{}})
	if !errors.As(err, &diagnostic) || diagnostic.Value.Code != projectverify.TrustCode {
		t.Fatalf("closed downgrade: %v", err)
	}
}

type wrappedNativeCAS struct{ r *trustload.Runtime }

func (w wrappedNativeCAS) Read(ctx context.Context, ref string) ([]byte, error) {
	return w.r.Read(ctx, ref)
}

func TestNativeVerifyCLIUncoveredInstalledAuthority(t *testing.T) {
	first, firstRoot := installedNativeGenCLI(t)
	firstHome := os.Getenv(state.HomeEnv)
	if out, err := executeNativeGenCLI(first, "gen", "note", "OwnerNote", "--label=one", "--no-build", "--json"); err != nil {
		t.Fatalf("first signed gen: %v %s", err, out)
	}
	second, secondRoot := installedNativeGenCLI(t)
	secondHome := os.Getenv(state.HomeEnv)
	// Initialize the second authority only through a genuine admitted operation.
	// No Inspector/key-creation helper or unsigned ownership label is injected.
	if out, err := executeNativeGenCLI(second, "gen", "note", "OtherNote", "--label=two", "--no-build", "--json"); err != nil {
		t.Fatalf("second signed gen: %v %s", err, out)
	}
	nativeVerifyCLI(t, second, secondRoot, secondHome, "", resultdto.ExitSuccess)
	t.Setenv(state.HomeEnv, firstHome)
	before := nativeVerifySnapshot(t, firstRoot, firstHome, secondRoot, secondHome)
	nativeVerifyCLI(t, second, secondRoot, firstHome, projectverify.TransactionCode, resultdto.ExitTransaction)
	nativeVerifyUnchanged(t, before, firstRoot, firstHome, secondRoot, secondHome)
	t.Setenv(state.HomeEnv, secondHome)
	nativeVerifyCLI(t, second, secondRoot, secondHome, "", resultdto.ExitSuccess)
}
