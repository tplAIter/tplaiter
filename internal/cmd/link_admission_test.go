package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func linkAdmissionFixture(t *testing.T, extras ...string) (t5FFixture, *trustload.Runtime, string, linkcmd.Input) {
	t.Helper()
	return linkAdmissionFixtureWithDirectories(t, false, extras...)
}
func linkAdmissionFixtureWithDirectories(t *testing.T, directories bool, extras ...string) (t5FFixture, *trustload.Runtime, string, linkcmd.Input) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	f := nativeLinkCLIFixture(t, directories, extras...)
	home := filepath.Join(filepath.Dir(f.projectRoot), "admission-home")
	if e := os.Mkdir(home, 0o700); e != nil {
		t.Fatal(e)
	}
	in := invocation{Selection: f.selection, ProjectKey: "project", Clock: f.clock}
	provision := newTrustRootCommand(in)
	provision.SetOut(&bytes.Buffer{})
	provision.SetErr(&bytes.Buffer{})
	provision.SetArgs([]string{"trust", "provision"})
	if e := provision.Execute(); e != nil {
		t.Fatal(e)
	}
	r, e := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: bootstrap.ClockFunc(time.Now)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	for name, b := range map[string][]byte{"go.mod": []byte("module example.test/adopt\ngo 1.26\n"), "added.txt": []byte("new owned\n")} {
		if e = os.WriteFile(filepath.Join(f.projectRoot, name), b, 0o644); e != nil {
			t.Fatal(e)
		}
	}
	if directories {
		for _, dir := range []string{"aa", "bb"} {
			if e = os.Mkdir(filepath.Join(f.projectRoot, dir), 0o755); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(f.projectRoot, dir, "note.txt"), []byte("signed directory\n"), 0o644); e != nil {
				t.Fatal(e)
			}
		}
	}
	return f, r, home, linkcmd.Input{Action: "link", Ref: f.target.Commit, Name: "Adopt", Module: "example.test/adopt", Source: t5FSelection(f.target, f.targetRefs), Choices: map[string]string{}}
}
func TestLinkAdmissionRefusesStaleInodeAndCancellation(t *testing.T) {
	f, r, home, in := linkAdmissionFixture(t)
	ctx := context.Background()
	p, e := linkcmd.Prepare(ctx, r, home, in, "dev")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(f.projectRoot, "go.mod")
	before, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	held := filepath.Join(filepath.Dir(f.projectRoot), "original-go.mod")
	if e = os.Rename(path, held); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0o644); e != nil {
		t.Fatal(e)
	}
	tx, e := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
	if tx != nil {
		tx.Release()
	}
	if e == nil {
		t.Fatal("same bytes foreign inode admitted")
	}
	if _, e = os.Lstat(filepath.Join(f.projectRoot, ".tplaiter")); !os.IsNotExist(e) {
		t.Fatal("stale plan changed project")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(held, path); e != nil {
		t.Fatal(e)
	}
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("lost preserved beforeimage")
	}
	for _, deadline := range []bool{false, true} {
		var stopped context.Context
		var cancel context.CancelFunc
		want := context.Canceled
		if deadline {
			stopped, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			stopped, cancel = context.WithCancel(ctx)
			cancel()
		}
		plan, e := linkcmd.Prepare(stopped, r, home, in, "dev")
		cancel()
		if !errors.Is(e, want) || plan != nil {
			t.Fatalf("cancel/deadline %v", e)
		}
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if p, e := linkcmd.Prepare(ctx, r, home, in, "dev"); e == nil || p != nil {
		t.Fatal("closed runtime admitted")
	}
}
func TestLinkRefusesSignedDeclaredActionsAndIrrelevantChoices(t *testing.T) {
	_, r, home, in := linkAdmissionFixture(t, "hooks:\n  postCreate: [\"touch executed\"]\n")
	if p, e := linkcmd.Prepare(context.Background(), r, home, in, "dev"); e == nil || p != nil {
		t.Fatal("signed hook admitted")
	}
	if _, e := os.Lstat(filepath.Join(r.ProjectContext().RootPath, "executed")); !os.IsNotExist(e) {
		t.Fatal("hook executed")
	}
	_, r, home, in = linkAdmissionFixture(t)
	in.Choices["extra.txt"] = "track"
	if p, e := linkcmd.Prepare(context.Background(), r, home, in, "dev"); !errors.Is(e, linkcmd.ErrInput) || p != nil {
		t.Fatalf("irrelevant ownership decision: %v", e)
	}
}

// Even an already admitted live handle cannot overwrite a changed receipt.
func TestLinkLiveReceiptTamperRefusesBeforePublication(t *testing.T) {
	f, r, home, in := linkAdmissionFixture(t)
	ctx := context.Background()
	p, err := linkcmd.Prepare(ctx, r, home, in, "dev")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
	if tx != nil {
		defer tx.Release()
	}
	if err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(home, "transactions", "project", "tx-"+tx.ID(), "state.json")
	raw, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte("prepared"), []byte("committed"), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("missing prepared phase")
	}
	if err = os.WriteFile(receipt, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("live tampered receipt authorized publication")
	}
	if got, err := os.ReadFile(receipt); err != nil || !bytes.Equal(got, tampered) {
		t.Fatal("tampered receipt overwritten")
	}
	if _, err = os.Lstat(filepath.Join(f.projectRoot, ".tplaiter")); !os.IsNotExist(err) {
		t.Fatal("live tamper published managed state")
	}
	if _, err = os.Lstat(filepath.Join(home, "projects.yaml")); !os.IsNotExist(err) {
		t.Fatal("live tamper published registry")
	}
}

func TestLinkLiveImmutablePlanRefusals(t *testing.T) {
	for _, change := range []string{"content", "equal-bytes-foreign-inode", "removed"} {
		t.Run(change, func(t *testing.T) {
			f, r, home, in := linkAdmissionFixture(t)
			ctx := context.Background()
			p, err := linkcmd.Prepare(ctx, r, home, in, "dev")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
			if tx != nil {
				defer tx.Release()
			}
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(home, "transactions", "project", "tx-"+tx.ID())
			plan := filepath.Join(dir, "plan.json")
			original, err := os.ReadFile(plan)
			if err != nil {
				t.Fatal(err)
			}
			held := filepath.Join(filepath.Dir(f.projectRoot), "retained-plan.json")
			switch change {
			case "content":
				if err = os.WriteFile(plan, []byte("corrupt immutable journal"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "equal-bytes-foreign-inode", "removed":
				if err = os.Rename(plan, held); err != nil {
					t.Fatal(err)
				}
				if change == "equal-bytes-foreign-inode" {
					if err = os.WriteFile(plan, original, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			stage := filepath.Join(filepath.Dir(f.projectRoot), "."+filepath.Base(f.projectRoot)+"-tplaiter-link-"+tx.ID())
			before := linkNegativeSnapshot(t, dir, stage, f.projectRoot)
			if err = tx.Commit(ctx); err == nil {
				t.Fatal("changed immutable journal authorized live Commit")
			}
			if err = tx.Abort(ctx); err == nil {
				t.Fatal("changed immutable journal authorized live Abort")
			}
			assertLinkNegativeSnapshot(t, before, dir, stage, f.projectRoot)
			assertLinkUnpublished(t, f.projectRoot, home)
			tx.Release()
			cold, err := linktx.Open(ctx, r, home, tx.ID(), "dev")
			if cold != nil {
				cold.Release()
			}
			if err == nil {
				t.Fatal("changed immutable journal authorized cold recovery")
			}
			assertLinkNegativeSnapshot(t, before, dir, stage, f.projectRoot)
			if change != "content" {
				got, err := os.ReadFile(held)
				if err != nil || !bytes.Equal(got, original) {
					t.Fatal("retained original evidence changed")
				}
			}
			t.Logf("%s: live Commit/Abort and cold Open refused; changed journal/stage/user evidence preserved", change)
		})
	}
}
func TestLinkLiveFullModeRefusals(t *testing.T) {
	for _, path := range []string{"go.mod", ".", "aa"} {
		for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky, 0o040} {
			if path == "go.mod" && mode == 0o040 {
				continue
			}
			t.Run(path+"/"+mode.String(), func(t *testing.T) {
				f, r, home, in := linkAdmissionFixtureWithDirectories(t, true)
				ctx := context.Background()
				p, err := linkcmd.Prepare(ctx, r, home, in, "dev")
				if err != nil {
					t.Fatal(err)
				}
				tx, err := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
				if tx != nil {
					defer tx.Release()
				}
				if err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(f.projectRoot, path)
				info, err := os.Lstat(name)
				if err != nil {
					t.Fatal(err)
				}
				want := info.Mode() | mode
				if mode == 0o040 {
					want = info.Mode() ^ mode
				}
				if err = os.Chmod(name, want); err != nil {
					t.Fatal(err)
				}
				changed, err := os.Lstat(name)
				if err != nil || changed.Mode() == info.Mode() {
					t.Fatal("filesystem did not apply requested mode change")
				}
				dir := filepath.Join(home, "transactions", "project", "tx-"+tx.ID())
				stage := filepath.Join(filepath.Dir(f.projectRoot), "."+filepath.Base(f.projectRoot)+"-tplaiter-link-"+tx.ID())
				before := linkNegativeSnapshot(t, dir, stage, f.projectRoot)
				if err = tx.Commit(ctx); err == nil {
					t.Fatal("post-seal mode change authorized publication")
				}
				if err = tx.Abort(ctx); err == nil {
					t.Fatal("post-seal mode change authorized rollback advancement")
				}
				assertLinkUnpublished(t, f.projectRoot, home)
				assertLinkNegativeSnapshot(t, before, dir, stage, f.projectRoot)
				t.Logf("post-Begin %s mode=%s: Commit/Abort refused; changed mode and all evidence preserved", path, changed.Mode())
			})
		}
	}
}
func TestLinkInitialSpecialModeContract(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		t.Run(mode.String(), func(t *testing.T) {
			f, r, home, in := linkAdmissionFixtureWithDirectories(t, true)
			ctx := context.Background()
			path := filepath.Join(f.projectRoot, "go.mod")
			if err := os.Chmod(path, 0o644|mode); err != nil {
				t.Fatal(err)
			}
			if p, err := linkcmd.Prepare(ctx, r, home, in, "dev"); err == nil || p != nil {
				t.Fatal("initial special regular mode accepted")
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			rootInfo, err := os.Lstat(f.projectRoot)
			if err != nil {
				t.Fatal(err)
			}
			want := rootInfo.Mode() | mode
			if err = os.Chmod(f.projectRoot, want); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(f.projectRoot)
			if err != nil || info.Mode() != want {
				t.Fatal("initial directory bit not set")
			}
			p, err := linkcmd.Prepare(ctx, r, home, in, "dev")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := linktx.Begin(ctx, p, p.Fingerprint(), "dev")
			if tx != nil {
				defer tx.Release()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(f.projectRoot)
			if err != nil || after.Mode() != want || !os.SameFile(info, after) {
				t.Fatal("initial directory special mode/inode not preserved")
			}
			t.Logf("initial regular %s refused; unchanged directory %s accepted and preserved", mode, mode)
		})
	}
}
func assertLinkUnpublished(t *testing.T, root, home string) {
	t.Helper()
	for _, name := range []string{filepath.Join(root, ".tplaiter"), filepath.Join(home, "projects.yaml")} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatalf("unexpected publication %s: %v", name, err)
		}
	}
}
func linkNegativeSnapshot(t *testing.T, roots ...string) map[string]linkObservedFile {
	t.Helper()
	out := map[string]linkObservedFile{}
	for _, root := range roots {
		err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			var raw []byte
			if !info.IsDir() {
				raw, err = os.ReadFile(name)
				if err != nil {
					return err
				}
			}
			out[name] = linkObservedFile{info, raw}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func assertLinkNegativeSnapshot(t *testing.T, before map[string]linkObservedFile, roots ...string) {
	t.Helper()
	after := linkNegativeSnapshot(t, roots...)
	if len(after) != len(before) {
		t.Fatal("evidence path inventory changed")
	}
	for name, want := range before {
		got, ok := after[name]
		if !ok || !os.SameFile(got.info, want.info) || got.info.Mode() != want.info.Mode() || !bytes.Equal(got.raw, want.raw) {
			t.Fatalf("changed evidence %s", name)
		}
	}
}
