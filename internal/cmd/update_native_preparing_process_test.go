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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

type preparingChildInput struct {
	Selection trustload.LaunchSelection `json:"selection"`
	Key       string                    `json:"key"`
	Home      string                    `json:"home"`
	Source    []byte                    `json:"source"`
	Target    []byte                    `json:"target"`
	Minimum   int                       `json:"minimum"`
	Ready     string                    `json:"ready"`
}

type preparingReady struct {
	ID     string            `json:"id"`
	Prefix int               `json:"prefix"`
	Report updateplan.Report `json:"report"`
}

// This context pauses only after observing a real durable signed staging
// prefix. The parent kills this process before any Continue or publication.
// Observing progress is a test schedule, never an admission or phase grant.
type preparingKillContext struct {
	context.Context
	input  preparingChildInput
	report updateplan.Report
	prior  map[string]bool
}

func (c *preparingKillContext) Err() error {
	names, _ := filepath.Glob(filepath.Join(c.input.Home, "transactions", "project", "tx-*", "state.json"))
	for _, name := range names {
		if c.prior[name] {
			continue
		}
		raw, err := os.ReadFile(name)
		var record struct {
			Payload struct {
				ID    string            `json:"id"`
				Phase string            `json:"phase"`
				Steps []json.RawMessage `json:"steps"`
			} `json:"payload"`
		}
		if err == nil && json.Unmarshal(raw, &record) == nil && record.Payload.Phase == "preparing" && len(record.Payload.Steps) >= c.input.Minimum {
			ready, err := json.Marshal(preparingReady{ID: record.Payload.ID, Prefix: len(record.Payload.Steps), Report: c.report})
			if err != nil {
				return err
			}
			if err := os.WriteFile(c.input.Ready, ready, 0o600); err != nil {
				return err
			}
			<-c.Done()
			return c.Context.Err()
		}
	}
	return c.Context.Err()
}

func TestNativeUpdatePreparingStagingChild(t *testing.T) {
	name := os.Getenv("TPLAITER_PREPARING_CHILD_INPUT")
	if name == "" {
		return
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var input preparingChildInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	in := invocation{Selection: input.Selection, ProjectKey: input.Key, Clock: bootstrap.ClockFunc(time.Now)}
	r, err := composeRuntimeForProject(withInvocation(context.Background(), in), input.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := updateplan.New(r, input.Home, resolveVersion())
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(context.Background(), updateplan.Input{SourceInput: input.Source, TargetInput: input.Target})
	if err != nil {
		t.Fatalf("signed plan: %v renderer=%q source-bytes=%d target-bytes=%d", err, resolveVersion(), len(input.Source), len(input.Target))
	}
	raw, err = p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var report updateplan.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if input.Minimum < 0 {
		input.Minimum = 0
		for _, change := range report.Changes {
			if change.Operation != "keep" {
				input.Minimum++
			}
		}
		if report.Registry.Before.SHA256 != report.Registry.After.SHA256 {
			input.Minimum++
		}
	}
	// A timer keeps this deliberately paused process alive until its parent kills
	// it, including under the race runtime's deadlock detection. Existing receipts
	// are excluded so a failed earlier fixture cannot select another project's ID.
	childCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	prior := map[string]bool{}
	names, _ := filepath.Glob(filepath.Join(input.Home, "transactions", "project", "tx-*", "state.json"))
	for _, name := range names {
		prior[name] = true
	}
	boundary := &preparingKillContext{Context: childCtx, input: input, report: report, prior: prior}
	tx, err := projecttransaction.BeginUpdate(boundary, p, p.Fingerprint())
	if tx != nil {
		tx.Release()
	}
	t.Fatalf("staging child returned instead of being killed: %v", err)
}

func TestNativeUpdatePreparingKilledContinue(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := nativeUpdateCLIFixtureWithDirectories(t, true)
	base := filepath.Dir(f.projectRoot)
	home := filepath.Join(base, "preparing-home")
	ledgerHome := filepath.Join(home, "tplaiter")
	var install trustload.RuntimeInstall
	raw, err := os.ReadFile(f.selection.RuntimeConfig.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &install); err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{}
	for _, key := range []string{"zero", "partial", "full", "abort", "cancel", "orphan"} {
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
	registration := ossinstall.Registration{APIVersion: "tplaiter.dev/installed-launch-registration/v1", Profile: f.selection.Profile, RuntimeConfig: f.selection.RuntimeConfig, OperatorRecord: f.selection.OperatorRecord, InstallationID: f.selection.InstallationID, ProjectKey: "zero"}
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
	// Pin the same real renderer build version in both executables. Go builds in
	// a Git tree otherwise stamp a pseudo-version absent from the test executable.
	build := exec.Command(testfixture.GoBinary(t), "build", "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.version="+resolveVersion()+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+registrationPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=sha256:"+hex.EncodeToString(digest[:]), "-o", bin, ".")
	build.Dir, build.Env = filepath.Join("..", ".."), testBuildEnv(home)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("installed build: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		child := exec.CommandContext(ctx, bin, args...)
		child.Env, child.Dir = testProcessEnv(home), base
		return child.Output()
	}
	if out, err := run("trust", "provision"); err != nil {
		t.Fatalf("provision: %v %s", err, out)
	}
	sourcePath := filepath.Join(base, "source.json")
	if err := os.WriteFile(sourcePath, t5FSelection(f.source, f.sourceRefs), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(state.HomeEnv, ledgerHome)
	observed := func(root string) map[string]string {
		result := nativeUpdateObservedTree(t, root)
		for prefix, other := range map[string]string{"home": ledgerHome, "objects": install.ObjectOrigins[0].RootPath, "evidence": install.EvidenceRoot} {
			for name, value := range nativeUpdateObservedTree(t, other) {
				result[prefix+"/"+name] = value
			}
		}
		return result
	}
	publication := func(root string) map[string]string {
		result := nativeUpdateObservedTree(t, root)
		for name := range result {
			if name == ".tplaiter/update.lock" || name == ".tplaiter/project-transactions" || strings.HasPrefix(name, ".tplaiter/project-transactions/") {
				delete(result, name)
			}
		}
		return result
	}
	for _, tc := range []struct {
		key     string
		minimum int
	}{{"zero", 0}, {"partial", 3}, {"full", -1}, {"abort", 3}, {"cancel", 0}, {"orphan", 0}} {
		t.Run(tc.key, func(t *testing.T) {
			root := roots[tc.key]
			if out, err := run("new", f.source.Commit, "project", "--project-context", tc.key, "--dir", root, "--source-input", sourcePath, "--defaults", "--no-hooks", "--json"); err != nil {
				t.Fatalf("new: %v %s", err, out)
			}
			if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("local one\nbase two\nbase three\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			original := publication(root)
			registry, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			readyPath := filepath.Join(base, tc.key+"-ready.json")
			inputPath := filepath.Join(base, tc.key+"-child.json")
			input := preparingChildInput{Selection: f.selection, Key: tc.key, Home: ledgerHome, Source: t5FSelection(f.source, f.sourceRefs), Target: t5FSelection(f.target, f.targetRefs), Minimum: tc.minimum, Ready: readyPath}
			if err := os.WriteFile(inputPath, t5FJSON(t, input), 0o600); err != nil {
				t.Fatal(err)
			}
			testBin, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(ctx, testBin, "-test.run=^TestNativeUpdatePreparingStagingChild$", "-test.v")
			child.Env = append(testProcessEnv(home), "TPLAITER_PREPARING_CHILD_INPUT="+inputPath)
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			deadline := time.Now().Add(30 * time.Second)
			var ready preparingReady
			var waitErr error
			exited := false
			for time.Now().Before(deadline) {
				if raw, err := os.ReadFile(readyPath); err == nil && json.Unmarshal(raw, &ready) == nil && ready.ID != "" {
					break
				}
				select {
				case waitErr = <-done:
					exited = true
				default:
				}
				if exited {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var killErr error
			if !exited {
				killErr = child.Process.Kill()
				waitErr = <-done
			}
			if ready.ID == "" || killErr != nil || waitErr == nil {
				t.Fatalf("kill boundary: %v %v %s", killErr, waitErr, output.String())
			}
			if tc.minimum >= 0 && ready.Prefix != tc.minimum {
				t.Fatalf("prefix %d wanted %d", ready.Prefix, tc.minimum)
			}
			currentRegistry, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
			if err != nil || !bytes.Equal(registry, currentRegistry) || !reflect.DeepEqual(original, publication(root)) {
				t.Fatal("killed staging published project or registry")
			}
			t.Logf("killed actual signed staging child: prefix=%d id=%s", ready.Prefix, ready.ID)
			command := []string{"update", "continue", ready.ID, "--project-context", tc.key, "--dir", root, "--json"}
			if tc.key == "zero" {
				before := observed(root)
				out, err := run(append(command, "--dir", base)...)
				if err == nil || len(decodeOne(t, string(out)).Changes) != 0 || !reflect.DeepEqual(before, observed(root)) {
					t.Fatalf("wrong-root effect: %v %s", err, out)
				}
			}
			if tc.key == "orphan" {
				orphan := filepath.Join(root, ".tplaiter", "project-transactions", ready.ID, "000000")
				if err := os.WriteFile(orphan, []byte("foreign orphan"), 0o600); err != nil {
					t.Fatal(err)
				}
				before := observed(root)
				out, err := run(command...)
				env := decodeOne(t, string(out))
				if err == nil || env.Diagnostics[0].Code != "TPL-E-NATIVE-UPDATE-TRANSACTION" || !reflect.DeepEqual(before, observed(root)) {
					t.Fatalf("orphan was adopted: %v %s", err, out)
				}
			}
			if tc.key == "cancel" {
				boundary := &nativeUpdateBoundaryCancel{Context: ctx, home: ledgerHome, phase: "preparing", minimum: 1}
				in := invocation{Selection: f.selection, ProjectKey: tc.key, Clock: f.clock}
				c := newTrustRootCommand(in) //nolint:contextcheck // This existing test composition seam builds the actual tree; ExecuteContext supplies the observed cancellation context.
				var out bytes.Buffer
				c.SetOut(&out)
				c.SetErr(&out)
				c.SetArgs(command)
				if err := c.ExecuteContext(withInvocation(boundary, in)); !errors.Is(err, context.Canceled) || exitCodeFor(err) != resultdto.ExitTransaction || !boundary.fired { //nolint:contextcheck // The synthetic observer inherits ctx and only schedules cancellation of concrete staging.
					t.Fatalf("Continue cancellation: %v %s", err, out.String())
				}
			}
			if tc.key == "abort" || tc.key == "cancel" || tc.key == "orphan" {
				command[1] = "abort"
				for i := 0; i < 2; i++ {
					if out, err := run(command...); err != nil {
						t.Fatalf("cold Abort: %v %s", err, out)
					}
				}
				actual, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
				if err != nil || !bytes.Equal(registry, actual) || !reflect.DeepEqual(original, publication(root)) {
					t.Fatal("Abort did not preserve exact project and registry")
				}
				return
			}
			out, err := run(command...)
			if err != nil {
				t.Fatalf("cold Continue: %v %s", err, out)
			}
			env := decodeOne(t, string(out))
			if env.Operation != resultdto.OperationUpdateContinue || env.TransactionID == nil || *env.TransactionID != ready.ID || env.Status != resultdto.StatusOK {
				t.Fatalf("Continue result: %s", out)
			}
			expectedPaths := map[string]bool{}
			changedPaths := map[string]bool{}
			for name := range original {
				expectedPaths[name] = true
			}
			for _, change := range ready.Report.Changes {
				name := filepath.Join(root, change.Path)
				if change.Operation != "keep" {
					changedPaths[change.Path] = true
				}
				switch change.Operation {
				case "delete":
					delete(expectedPaths, change.Path)
					if _, err := os.Lstat(name); !os.IsNotExist(err) {
						t.Fatalf("deletion %s: %v", name, err)
					}
				case "keep":
					continue
				default:
					expectedPaths[change.Path] = true
					// Signed file paths also require their missing parent directories;
					// these are concrete engine steps, not separate report decisions.
					for parent := filepath.Dir(change.Path); parent != "."; parent = filepath.Dir(parent) {
						expectedPaths[parent] = true
						if _, exists := original[parent]; !exists {
							changedPaths[parent] = true
							info, err := os.Lstat(filepath.Join(root, parent))
							if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
								t.Fatalf("derived parent directory %s: %v", parent, err)
							}
						}
					}
					info, err := os.Lstat(name)
					if err != nil || change.After == nil || uint32(info.Mode().Perm()) != change.After.Mode || info.IsDir() != (change.After.Kind == "directory") {
						t.Fatalf("afterimage %s: %v", name, err)
					}
					if !info.IsDir() {
						actual, err := os.ReadFile(name)
						if err != nil || !bytes.Equal(actual, change.Content) {
							t.Fatalf("afterimage content %s", name)
						}
					}
				}
			}
			published := publication(root)
			if len(published) != len(expectedPaths) {
				t.Fatal("published project contains missing or unexpected paths")
			}
			for name, observation := range published {
				if !expectedPaths[name] || !changedPaths[name] && observation != original[name] {
					t.Fatalf("unplanned project effect: %s", name)
				}
			}
			actual, err := os.ReadFile(filepath.Join(ledgerHome, "projects.yaml"))
			if err != nil || !bytes.Equal(actual, ready.Report.Registry.AfterContent) {
				t.Fatal("registry afterimage differs from signed plan")
			}
			before := observed(root)
			if out, err := run(command...); err != nil || !reflect.DeepEqual(before, observed(root)) {
				t.Fatalf("cold terminal repeat: %v %s", err, out)
			}
			t.Logf("prefix %s committed exact project+registry; repeated cold confirmation preserved inventory", strconv.Itoa(ready.Prefix))
		})
	}
}
