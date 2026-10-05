//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func signedUpdateEngine(t *testing.T) (*Transaction, *t5DIntegrationFixture, *trustload.Runtime, string) {
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
	if err := newcmd.Run(ctx, newcmd.Options{Ref: f.source.Commit, ProjectName: "Ordinary Project", Dir: f.project, Module: "example.test/ordinary", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1"}, newcmd.Deps{Runtime: r, Home: home, SourceInput: t5DSelection(f.source, f.sourceRefs), Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	b, err := updateplan.New(r, home, "v1")
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, updateplan.Input{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := p.TransactionMaterial(ctx, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := Acquire(ctx, r, NativeUpdateKind, updateTestMaterial(t, m))
	if err != nil {
		t.Fatal(err)
	}
	m, _, err = p.TransactionMaterialAfterLease(ctx, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, "v1", m); err != nil {
		t.Fatal(err)
	}
	material := updateTestMaterial(t, m)
	if err := tx.ValidateLocked(ctx, material); err != nil {
		t.Fatal(err)
	}
	if err := tx.Seal(ctx, material); err != nil {
		t.Fatal(err)
	}
	return tx, f, r, home
}

func updateTestMaterial(t *testing.T, m updateplan.UpdateMaterial) Material {
	t.Helper()
	raw, err := canonicaljson.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(in map[string]updateplan.UpdateFile) map[string]File {
		out := map[string]File{}
		for p, f := range in {
			out[p] = File{Data: append(Bytes{}, f.Data...), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
		}
		return out
	}
	return Material{Root: m.Root, Home: m.Home, ProjectID: m.ProjectID, Binding: m.Binding, Before: convert(m.Before), After: convert(m.After), Fingerprint: m.Fingerprint, ReadOnlyPaths: []string{}, Intent: raw, Registry: &RegistryPair{Before: File{Data: append(Bytes{}, m.Registry.BeforeContent...), Mode: m.Registry.Before.Mode, Device: m.RegistryDevice, Inode: m.RegistryInode}, After: File{Data: append(Bytes{}, m.Registry.AfterContent...), Mode: m.Registry.After.Mode}}}
}

func coldSignedUpdate(t *testing.T, r *trustload.Runtime, home, id string) *Transaction {
	t.Helper()
	tx, err := Open(context.Background(), r, NativeUpdateKind, home, id)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tx.CheckedMaterial()
	if err != nil {
		t.Fatal(err)
	}
	var intent updateplan.UpdateMaterial
	if err := canonicaljson.DecodeStrict(m.Intent, &intent); err != nil {
		t.Fatal(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(context.Background(), r, "v1", intent); err != nil {
		t.Fatal(err)
	}
	a, _ := canonicaljson.Canonical(m)
	b, _ := canonicaljson.Canonical(updateTestMaterial(t, intent))
	if !bytes.Equal(a, b) {
		t.Fatal("receipt differs from signed reconstruction")
	}
	if err := tx.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tx
}

func assertUpdateBefore(t *testing.T, tx *Transaction, foreign string) {
	t.Helper()
	assertOriginalImages(t, tx, foreign)
	if foreign != "registry" {
		r := tx.plan.Material.Registry
		if err := checkPath(filepath.Join(tx.plan.Material.Home, "projects.yaml"), r.Before, Identity{r.Before.Device, r.Before.Inode}); err != nil {
			t.Fatal("exact registry beforeimage not restored", err)
		}
	}
}

type updateBoundaryContext struct {
	context.Context
	tx    *Transaction
	which string
	fired atomic.Bool
	once  sync.Once
	fault func()
}

func (c *updateBoundaryContext) Err() error {
	raw, err := os.ReadFile(filepath.Join(c.tx.dir, "state.json"))
	var record envelope
	var state progress
	if err == nil && json.Unmarshal(raw, &record) == nil && json.Unmarshal(record.Payload, &state) == nil && state.Phase == "applying" {
		for _, s := range state.Steps {
			if s.Intent && !s.Done && ((c.which == "delete" && s.Delete) || (c.which == "registry" && s.Registry)) {
				c.once.Do(func() { c.fired.Store(true); c.fault() })
				break
			}
		}
	}
	return c.Context.Err()
}

func TestSignedUpdatePublicationForeignRaces(t *testing.T) {
	for _, which := range []string{"delete", "registry"} {
		t.Run(which, func(t *testing.T) {
			tx, f, _, home := signedUpdateEngine(t)
			defer tx.Release()
			name := filepath.Join(f.project, "hello.txt")
			foreign := "hello.txt"
			if which == "registry" {
				name = filepath.Join(home, "projects.yaml")
				foreign = "registry"
			}
			var info os.FileInfo
			ctx := &updateBoundaryContext{Context: context.Background(), tx: tx, which: which}
			ctx.fault = func() {
				if err := os.Rename(name, name+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("foreign raced"), 0o600); err != nil {
					t.Fatal(err)
				}
				info, _ = os.Stat(name)
			}
			if err := tx.Commit(ctx); !errors.Is(err, ErrConflict) {
				t.Fatalf("race not preserved: %v", err)
			}
			if !ctx.fired.Load() {
				t.Fatal("publication boundary not reached")
			}
			after, err := os.Stat(name)
			if err != nil || !os.SameFile(info, after) {
				t.Fatal("foreign inode overwritten")
			}
			raw, _ := os.ReadFile(name)
			if string(raw) != "foreign raced" {
				t.Fatal("foreign bytes overwritten")
			}
			assertUpdateBefore(t, tx, foreign)
		})
	}
}

func TestSignedUpdateKilledPublicationRecovery(t *testing.T) {
	for _, boundary := range []string{"delete", "registry"} {
		for _, abort := range []bool{false, true} {
			t.Run(boundary+strconv.FormatBool(abort), func(t *testing.T) {
				tx, f, r, home := signedUpdateEngine(t)
				id := tx.ID()
				selection, _ := json.Marshal(f.selection)
				if err := os.WriteFile(filepath.Join(home, "update-launch.json"), selection, 0o600); err != nil {
					t.Fatal(err)
				}
				tx.Release()
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				child := exec.Command(executable, "-test.run=^TestSignedUpdateCrashChild$", "-test.timeout=45s")
				child.Env = []string{"TPLAITER_UPDATE_HOME=" + home, "TPLAITER_UPDATE_ID=" + id, "TPLAITER_UPDATE_BOUNDARY=" + boundary}
				output, err := child.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 77 {
					t.Fatalf("child did not crash at boundary: %v %s", err, output)
				}
				fresh, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
				if err != nil {
					t.Fatal(err)
				}
				defer fresh.Close()
				_ = r
				cold := coldSignedUpdate(t, fresh, home, id)
				defer cold.Release()
				if abort {
					if err := cold.Rollback(context.Background()); err != nil {
						t.Fatal(err)
					}
					assertUpdateBefore(t, cold, "")
				} else {
					if err := cold.Commit(context.Background()); err != nil {
						t.Fatal(err)
					}
					for _, s := range cold.state.Steps {
						if err := cold.checkStepFinal(s); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func TestSignedUpdateCrashChild(t *testing.T) {
	home := os.Getenv("TPLAITER_UPDATE_HOME")
	if home == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(home, "update-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	tx := coldSignedUpdate(t, r, home, os.Getenv("TPLAITER_UPDATE_ID"))
	tx.state.Phase = "applying"
	if err := tx.save(); err != nil {
		t.Fatal(err)
	}
	boundary := os.Getenv("TPLAITER_UPDATE_BOUNDARY")
	for i := range tx.state.Steps {
		s := &tx.state.Steps[i]
		if (boundary == "delete" && s.Delete) || (boundary == "registry" && s.Registry) {
			s.Intent = true
			if err := tx.save(); err != nil {
				t.Fatal(err)
			}
			var err error
			if s.Delete {
				err = tx.quarantine(*s)
			} else {
				err = tx.publish(*s, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			os.Exit(77) // Actual process death before completion record, no Release.
		}
		if err := tx.applyStep(context.Background(), i); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("crash boundary missing")
}

func TestSignedNativeJournalAdmissionGuard(t *testing.T) {
	ctx := context.Background()
	r, home, _ := nativeSignedProject(t)
	p := nativePlan(t, r, home)
	tx, err := beginSignedNative(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tx.CheckedMaterial()
	if err != nil {
		t.Fatal(err)
	}
	tx.Release()
	second, err := Acquire(ctx, r, NativeGeneratorKind, m)
	if second != nil {
		second.Release()
	}
	if !errors.Is(err, ErrActive) {
		t.Fatalf("unresolved gen journal accepted: %v", err)
	}
	old, err := openSignedNative(ctx, r, home, tx.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	old.Release()
	second, err = Acquire(ctx, r, NativeGeneratorKind, m)
	if err != nil {
		t.Fatalf("terminal receipt blocked next native admission: %v", err)
	}
	defer second.Release()
	// The second check occurs after operation-specific fresh reconstruction.
	prior := &Transaction{key: second.key, dir: tx.dir, plan: tx.plan, state: tx.state}
	prior.state.Phase = "prepared"
	if err := prior.save(); err != nil {
		t.Fatal(err)
	}
	if err := second.Seal(ctx, m); !errors.Is(err, ErrActive) {
		t.Fatalf("late unresolved receipt passed Seal: %v", err)
	}
}

func TestSignedUpdateRollbackReceiptRetry(t *testing.T) {
	for _, fault := range []commitWriteFault{commitWriteBeforePublish, commitWriteAfterPublish} {
		t.Run(strconv.Itoa(int(fault)), func(t *testing.T) {
			tx, _, r, home := signedUpdateEngine(t)
			if err := tx.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			tx.rollbackFault = fault
			if err := tx.Rollback(context.Background()); !errors.Is(err, errCommitWriteFault) {
				t.Fatalf("terminal failure: %v", err)
			}
			if tx.state.Phase == "rolled-back" {
				t.Fatal("false terminal rollback success")
			}
			tx.rollbackFault = commitWriteOK
			if err := tx.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			tx.Release()
			cold := coldSignedUpdate(t, r, home, tx.ID())
			defer cold.Release()
			if err := cold.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSignedUpdatePreparingColdAbort(t *testing.T) {
	tx, _, r, home := signedUpdateEngine(t)
	// A receipt persisted after only the first staged step is a valid preparing
	// prefix; unpublished orphan stage images grant no ownership of project paths.
	tx.state.Phase = "preparing"
	tx.state.Steps = tx.state.Steps[:1]
	if err := tx.save(); err != nil {
		t.Fatal(err)
	}
	tx.Release()
	cold := coldSignedUpdate(t, r, home, tx.ID())
	if err := cold.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	cold.Release()
	terminal := coldSignedUpdate(t, r, home, tx.ID())
	defer terminal.Release()
	if err := terminal.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSignedUpdateColdRollbackUncertainReceipt(t *testing.T) {
	tx, f, _, home := signedUpdateEngine(t)
	ctx := context.Background()
	if err := tx.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	tx.rollbackFault = commitWriteAfterPublish
	if err := tx.Rollback(ctx); !errors.Is(err, errCommitWriteFault) {
		t.Fatalf("uncertain terminal publication: %v", err)
	}
	assertUpdateBefore(t, tx, "")
	id := tx.ID()
	tx.Release()
	fresh, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	cold := coldSignedUpdate(t, fresh, home, id)
	defer cold.Release()
	// No successful live rollback retry precedes this fresh-runtime reopen.
	cold.rollbackSyncFault = receiptSyncBeforeDirectory
	if err := cold.Rollback(ctx); !errors.Is(err, errReceiptSyncFault) {
		t.Fatalf("confirmation sync cause lost: %v", err)
	}
	assertUpdateBefore(t, cold, "")
	cold.rollbackSyncFault = receiptSyncOK
	if err := cold.Rollback(ctx); err != nil {
		t.Fatalf("cold durable confirmation: %v", err)
	}
	if err := cold.Rollback(ctx); err != nil {
		t.Fatalf("idempotent confirmed retry: %v", err)
	}
	name := filepath.Join(cold.dir, "state.json")
	retained := name + ".fault-retained"
	if err := os.Rename(name, retained); err != nil {
		t.Fatal(err)
	}
	if err := cold.Rollback(ctx); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing receipt falsely confirmed or cause lost: %v", err)
	}
	if err := os.WriteFile(name, []byte("foreign receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := cold.Rollback(ctx); err == nil {
		t.Fatal("foreign replacement falsely confirmed")
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(foreign, after) {
		t.Fatal("confirmation modified foreign receipt inode")
	}
	raw, err := os.ReadFile(name)
	if err != nil || string(raw) != "foreign receipt" {
		t.Fatal("confirmation changed foreign receipt bytes")
	}
	// A different valid signed phase is also not the admitted terminal receipt.
	cold.state.Phase = "prepared"
	if err := cold.writeSigned("state.json", cold.state, false); err != nil {
		t.Fatal(err)
	}
	cold.state.Phase = "rolled-back"
	if err := cold.Rollback(ctx); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("signed phase mismatch accepted: %v", err)
	}
	if err := os.Rename(retained, name); err != nil {
		t.Fatal(err)
	}
	if err := cold.Rollback(ctx); err != nil {
		t.Fatalf("retained exact receipt retry: %v", err)
	}
	assertUpdateBefore(t, cold, "")
}
