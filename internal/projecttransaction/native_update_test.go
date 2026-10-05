package projecttransaction

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"

	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestSignedUpdateFacadeApplyAndColdCommit(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t)
	ctx := context.Background()
	r, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
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
	input := updateplan.Input{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs)}
	foreign := filepath.Join(f.project, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := BeginUpdate(ctx, p, p.Fingerprint())
	if tx == nil || err != nil {
		t.Fatalf("signed writer refused: %v", err)
	}
	id := tx.ID()
	if id == "" {
		t.Fatal("no durable update receipt")
	}
	if err := tx.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	tx.Release()
	fresh, err := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	cold, err := OpenUpdate(ctx, fresh, home, id, "v1")
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Release()
	if err := cold.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(foreign)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatal("foreign inode/mode changed")
	}
	raw, err := os.ReadFile(foreign)
	if err != nil || string(raw) != "foreign" {
		t.Fatal("foreign bytes changed")
	}
	raw, err = os.ReadFile(filepath.Join(f.project, "hello.txt"))
	if err != nil || string(raw) != "hello target\nstable\n" {
		t.Fatalf("not actual target: %q %v", raw, err)
	}
	raw, err = os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil || bytes.Equal(registry, raw) {
		t.Fatal("registry was not published")
	}
	if err := cold.Commit(ctx); err != nil {
		t.Fatalf("durable terminal retry: %v", err)
	}
	cold.Release()
	// A terminal receipt must not block a legitimate next signed B→B operation.
	b, err = updateplan.New(fresh, home, "v1")
	if err != nil {
		t.Fatal(err)
	}
	beforeNoop, err := os.Stat(filepath.Join(f.project, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	noop, err := b.Prepare(ctx, updateplan.Input{SourceInput: t5DSelection(f.target, f.targetRefs), TargetInput: t5DSelection(f.target, f.targetRefs)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUpdate(ctx, noop, noop.Fingerprint()); err != nil {
		t.Fatalf("actual signed no-op refused: %v", err)
	}
	afterNoop, err := os.Stat(filepath.Join(f.project, "hello.txt"))
	if err != nil || !os.SameFile(beforeNoop, afterNoop) || beforeNoop.Mode() != afterNoop.Mode() {
		t.Fatal("no-op replaced unchanged owned image")
	}
}

func TestUpdateFacadeRejectsUnconstructedPlan(t *testing.T) {
	if _, err := BeginUpdate(context.Background(), &updateplan.Plan{}, "sha256:forged"); !errors.Is(err, updateplan.ErrInvalid) {
		t.Fatalf("caller data minted admission: %v", err)
	}
}

func signedUpdateCase(t *testing.T, deletion bool) (*t5DIntegrationFixture, *trustload.Runtime, string, *updateplan.Plan) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	writer := t5DWriteNativeSource
	if deletion {
		writer = func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
			return t5DWriteNativeSourceFiles(t, root, suffix, output, extra, map[string][]byte{"!delete:hello.txt.tmpl": nil, "new/empty.txt.tmpl": {}})
		}
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
	return f, r, home, p
}

func TestSignedUpdateDeletionAndColdAbort(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(strconv.FormatBool(abort), func(t *testing.T) {
			f, r, home, p := signedUpdateCase(t, true)
			ctx := context.Background()
			old, err := os.Stat(filepath.Join(f.project, "hello.txt"))
			if err != nil {
				t.Fatal(err)
			}
			registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			tx, err := BeginUpdate(ctx, p, p.Fingerprint())
			if err != nil {
				t.Fatal(err)
			}
			id := tx.ID()
			if err := tx.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			tx.Release()
			if _, err := os.Stat(filepath.Join(f.project, "hello.txt")); !os.IsNotExist(err) {
				t.Fatalf("owned deletion not published: %v", err)
			}
			cold, err := OpenUpdate(ctx, r, home, id, "v1")
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Release()
			if abort {
				if err := cold.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				restored, err := os.Stat(filepath.Join(f.project, "hello.txt"))
				if err != nil || !os.SameFile(old, restored) || old.Mode() != restored.Mode() {
					t.Fatal("rollback lost owned inode/mode")
				}
				raw, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
				if err != nil || !bytes.Equal(raw, registry) {
					t.Fatal("registry rollback lost exact before bytes")
				}
				if _, err := os.Stat(filepath.Join(f.project, "new")); !os.IsNotExist(err) {
					t.Fatal("owned empty parent not rolled back")
				}
			} else {
				if err := cold.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSignedUpdateForeignReplacementRollback(t *testing.T) {
	for _, where := range []string{"deleted path", "registry"} {
		t.Run(where, func(t *testing.T) {
			f, r, home, p := signedUpdateCase(t, true)
			ctx := context.Background()
			oldRegistry, _ := os.ReadFile(filepath.Join(home, "projects.yaml"))
			tx, err := BeginUpdate(ctx, p, p.Fingerprint())
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(f.project, "hello.txt")
			if where == "registry" {
				name = filepath.Join(home, "projects.yaml")
			}
			replacement := name + ".foreign"
			if err := os.WriteFile(replacement, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, name); err != nil {
				t.Fatal(err)
			}
			foreign, _ := os.Stat(name)
			if err := tx.Rollback(ctx); !errors.Is(err, ErrConflict) {
				t.Fatalf("foreign rollback: %v", err)
			}
			actual, err := os.Stat(name)
			if err != nil || !os.SameFile(foreign, actual) {
				t.Fatal("foreign inode lost")
			}
			raw, err := os.ReadFile(name)
			if err != nil || string(raw) != "foreign" {
				t.Fatal("foreign bytes lost")
			}
			tx.Release()
			// Fresh cold reauthentication can reopen ambiguity but cannot adopt it.
			cold, err := OpenUpdate(ctx, r, home, tx.ID(), "v1")
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Release()
			if err := cold.Rollback(ctx); !errors.Is(err, ErrConflict) {
				t.Fatalf("cold foreign classification: %v", err)
			}
			if where == "deleted path" {
				raw, _ := os.ReadFile(filepath.Join(home, "projects.yaml"))
				if !bytes.Equal(raw, oldRegistry) {
					t.Fatal("other registry image not rolled back")
				}
			}
		})
	}
}

func TestSignedUpdateCancelledAfterApplyRestoresPair(t *testing.T) {
	f, _, home, p := signedUpdateCase(t, true)
	registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(filepath.Join(f.project, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := BeginUpdate(context.Background(), p, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Release()
	if err := tx.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tx.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel result: %v", err)
	}
	restored, err := os.Stat(filepath.Join(f.project, "hello.txt"))
	if err != nil || !os.SameFile(original, restored) || restored.Mode() != original.Mode() {
		t.Fatal("cancel lost owned before inode/mode")
	}
	raw, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
	if err != nil || !bytes.Equal(raw, registry) {
		t.Fatal("cancel did not restore registry")
	}
}

func TestSignedUpdateColdReauthRefusesDrift(t *testing.T) {
	for _, drift := range []string{"current source", "target source", "installed policy", "renderer"} {
		t.Run(drift, func(t *testing.T) {
			f, r, home, p := signedUpdateCase(t, false)
			ctx := context.Background()
			tx, err := BeginUpdate(ctx, p, p.Fingerprint())
			if err != nil {
				t.Fatal(err)
			}
			id := tx.ID()
			tx.Release()
			hello, err := os.ReadFile(filepath.Join(f.project, "hello.txt"))
			if err != nil {
				t.Fatal(err)
			}
			registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			version := "v1"
			name := filepath.Join(f.dir, "objects", f.source.Commit)
			switch drift {
			case "target source":
				name = filepath.Join(f.dir, "objects", f.target.Commit)
			case "installed policy":
				name = filepath.Join(f.dir, "policy.json")
			case "renderer":
				version = "forged-version"
			}
			if drift != "renderer" {
				if err := os.WriteFile(name, []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cold, err := OpenUpdate(ctx, r, home, id, version)
			if cold != nil {
				cold.Release()
			}
			if err == nil {
				t.Fatal("drift minted cold update admission")
			}
			raw, err := os.ReadFile(filepath.Join(f.project, "hello.txt"))
			if err != nil || !bytes.Equal(raw, hello) {
				t.Fatal("refusal changed project")
			}
			raw, err = os.ReadFile(filepath.Join(home, "projects.yaml"))
			if err != nil || !bytes.Equal(raw, registry) {
				t.Fatal("refusal changed registry")
			}
		})
	}
}

func TestSignedUpdateActualThreeWay(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(strconv.FormatBool(conflict), func(t *testing.T) {
			f, r, home, _ := signedUpdateCase(t, false)
			local := []byte("hello source\nlocal\n")
			if conflict {
				local = []byte("hello user\nstable\n")
			}
			name := filepath.Join(f.project, "hello.txt")
			if err := os.WriteFile(name, local, 0o600); err != nil {
				t.Fatal(err)
			}
			original, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := os.ReadFile(filepath.Join(home, "projects.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := updateplan.New(r, home, "v1")
			if err != nil {
				t.Fatal(err)
			}
			p, err := b.Prepare(context.Background(), updateplan.Input{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs)})
			if err != nil {
				t.Fatal(err)
			}
			err = ApplyUpdate(context.Background(), p, p.Fingerprint())
			raw, readErr := os.ReadFile(name)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if conflict {
				if !errors.Is(err, updateplan.ErrConflict) {
					t.Fatalf("conflicting apply: %v", err)
				}
				current, statErr := os.Stat(name)
				if statErr != nil || !os.SameFile(original, current) || !bytes.Equal(local, raw) {
					t.Fatal("conflict replaced local bytes/inode")
				}
				after, readErr := os.ReadFile(filepath.Join(home, "projects.yaml"))
				if readErr != nil || !bytes.Equal(after, registry) {
					t.Fatal("conflict published registry")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if string(raw) != "hello target\nlocal\n" {
					t.Fatalf("incorrect actual merged bytes: %q", raw)
				}
			}
		})
	}
}
