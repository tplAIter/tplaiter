package updateplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/state"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func signedProject(t *testing.T, extras ...string) (*t5DIntegrationFixture, *Backend, Input) {
	t.Helper()
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t, extras...)
	return materializeSignedProject(t, f)
}

func materializeSignedProject(t *testing.T, f *t5DIntegrationFixture) (*t5DIntegrationFixture, *Backend, Input) {
	t.Helper()
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	home := filepath.Join(f.dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := newcmd.Run(context.Background(), newcmd.Options{Ref: f.source.Commit, ProjectName: "Ordinary Project", Dir: f.project, Module: "example.test/ordinary", Defaults: true, NoHooks: true, NoDepsCheck: true, CLIVersion: "v1"}, newcmd.Deps{Runtime: runtime, Home: home, SourceInput: t5DSelection(f.source, f.sourceRefs), Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	backend, err := New(runtime, home, "v1")
	if err != nil {
		t.Fatal(err)
	}
	return f, backend, Input{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs)}
}

func TestSignedNativePlanZeroWritesAndRecheck(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	homeBefore, err := observe(ctx, filepath.Join(f.dir, "home"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := observe(ctx, f.project)
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if p.report.Source.Root.Commit != f.source.Commit || p.report.Target.Root.Commit != f.target.Commit || p.report.Source.Root == p.report.Target.Root {
		t.Fatal("source and target were not independently retained")
	}
	var changed bool
	for _, c := range p.report.Changes {
		if c.Path == "hello.txt" && c.Operation == "write" && string(c.Content) == "hello target\nstable\n" {
			changed = true
		}
	}
	if !changed {
		t.Fatalf("missing actual target image: %+v", p.report.Changes)
	}
	after, err := observe(ctx, f.project)
	if err != nil || !equalObservation(before, after) {
		t.Fatalf("plan wrote project: %v", err)
	}
	homeAfter, err := observe(ctx, filepath.Join(f.dir, "home"))
	if err != nil || !equalObservation(homeBefore, homeAfter) {
		t.Fatalf("plan wrote registry/home: %v", err)
	}
	t5DAssertEmptyDir(t, f.scratch)
	if err := b.Recheck(ctx, p, p.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if _, err := p.Marshal(); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, "sha256:tampered"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered fingerprint: %v", err)
	}
	other, err := New(b.runtime, b.home, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay accepted: %v", err)
	}
	if err := b.Apply(ctx, p, p.Fingerprint()); !errors.Is(err, ErrApplyUnsupported) {
		t.Fatalf("unsafe apply seam used: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("stale foreign image accepted: %v", err)
	}
}

func TestSignedNativePlanNoopModifiedAndJournal(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	in.TargetInput = in.SourceInput
	if err := os.WriteFile(filepath.Join(f.project, "hello.txt"), []byte("local edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.report.Changes {
		if c.Operation != "keep" {
			t.Fatalf("no-op overwrites local bytes: %+v", c)
		}
	}
	if err := os.Chmod(filepath.Join(f.project, "hello.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("mode drift accepted: %v", err)
	}
	in.TargetInput = t5DSelection(f.target, f.targetRefs)
	p, err = b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(ctx, p, p.Fingerprint()); !errors.Is(err, ErrConflict) {
		t.Fatalf("mode conflict lost: %v", err)
	}
	if err := os.Mkdir(filepath.Join(f.project, ".tplaiter/update"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/update/active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prepare(ctx, in); err == nil {
		t.Fatal("pending journal accepted")
	}
}

func TestSignedNativePlanTamperMarkerAndOwnership(t *testing.T) {
	for _, test := range []string{"source", "target", "ownership", "marker", "manifest", "resources", "symlink", "cancel"} {
		t.Run(test, func(t *testing.T) {
			f, b, in := signedProject(t)
			ctx := context.Background()
			switch test {
			case "source":
				in.SourceInput = t5DSelection(f.target, f.targetRefs)
			case "target":
				in.TargetInput = t5DSelection(f.target, f.sourceRefs)
			case "ownership":
				if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/ownership.json"), []byte(`{"version":1,"artifacts":[]}`), 0o644); err != nil {
					t.Fatal(err)
				}
			case "marker":
				raw, err := os.ReadFile(filepath.Join(f.project, ".tplaiter/project.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.ReplaceAll(raw, []byte("project-t5d"), []byte("another-project"))
				if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/project.yaml"), raw, 0o644); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/manifest.snapshot.yaml"), []byte("changed"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "resources":
				if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/resources.lock.json"), []byte(`{"version":2}`), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("hello.txt", filepath.Join(f.project, "foreign-link")); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := b.Prepare(ctx, in); err == nil {
				t.Fatal("tampered input accepted")
			}
		})
	}
}

func TestSignedNativePlanDeniesUnapprovedTargetActions(t *testing.T) {
	_, b, in := signedProject(t, "", "hooks:\n  post_update:\n    - cmd: echo no\n")
	if _, err := b.Prepare(context.Background(), in); !errors.Is(err, operationtrust.ErrSourceAdapterUnsupported) {
		t.Fatalf("unsupported actions: %v", err)
	}
}

func TestOwnedThreeWayDecisions(t *testing.T) {
	o := &observation{files: map[string][]byte{"edited": []byte("user\nanchor\n"), "removed": []byte("edited"), "foreign": []byte("mine")}, images: []Image{{Path: "edited", Kind: "file", Mode: 0o644}, {Path: "removed", Kind: "file", Mode: 0o644}, {Path: "foreign", Kind: "file", Mode: 0o600}}}
	changes, err := computeChanges(o, map[string][]byte{"edited": []byte("base\nanchor\n"), "removed": []byte("old"), "deleted": []byte("old")}, map[string][]byte{"edited": []byte("base\ntarget\n"), "foreign": []byte("target"), "deleted": []byte("target")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		switch c.Path {
		case "edited":
			if string(c.Content) != "user\ntarget\n" || c.Conflict {
				t.Fatalf("independent edit lost: %+v", c)
			}
		case "removed", "deleted":
			if c.Operation != "keep" {
				t.Fatalf("local mutation lost: %+v", c)
			}
		case "foreign":
			if c.Operation != "keep" || !c.Conflict {
				t.Fatalf("foreign adopted: %+v", c)
			}
		}
	}
	raw, err := canonicaljson.Canonical(changes)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
}

func TestSignedNativePlanMergesAndSealsResources(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(f.project, "hello.txt"), []byte("hello source\nuser\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	var merged, resource, lock bool
	var resourceLock *resources.ResourceLockV2
	resourceFiles := map[string][]byte{}
	for _, c := range p.report.Changes {
		switch c.Path {
		case "hello.txt":
			merged = c.Operation == "write" && !c.Conflict && string(c.Content) == "hello target\nuser\n"
		case ".tplaiter/generators/generators/entity.tmpl":
			resource = c.Operation == "write" && string(c.Content) == "snippet-target\nstable\n"
			resourceFiles[c.Path] = c.Content
		case ".tplaiter/resources.lock.json":
			resourceLock, err = resources.DecodeResourceLockV2(c.Content)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Version        int    `json:"version"`
				RootLockSHA256 string `json:"rootLockSHA256"`
			}
			if err := json.Unmarshal(c.Content, &wire); err != nil {
				t.Fatal(err)
			}
			lock = wire.Version == 2 && wire.RootLockSHA256 == p.report.Target.RootLockSHA256
		}
	}
	if !merged || !resource || !lock {
		t.Fatalf("incomplete merge/resource images: merge=%v resource=%v lock=%v", merged, resource, lock)
	}
	if resourceLock == nil || len(resourceLock.Artifacts) != 1 || resourceLock.Artifacts[0].Source.Commit != f.target.Commit || resourceLock.Artifacts[0].Provider.Commit != f.target.Commit {
		t.Fatal("resource source/provider identity lost")
	}
	if err := (&resources.ResourceImages{Files: resourceFiles, Lock: *resourceLock}).Validate(p.report.Target); err != nil {
		t.Fatal(err)
	}
	resourcePath := filepath.Join(f.project, ".tplaiter/generators/generators/entity.tmpl")
	if err := os.WriteFile(resourcePath, []byte("local resource\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("resource drift accepted: %v", err)
	}
	p, err = b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(ctx, p, p.Fingerprint()); !errors.Is(err, ErrConflict) {
		t.Fatalf("resource conflict accepted: %v", err)
	}
}

func TestSignedNativePlanFreshAuthorityAndRootIdentity(t *testing.T) {
	for _, kind := range []string{"authority", "root"} {
		t.Run(kind, func(t *testing.T) {
			f, b, in := signedProject(t)
			ctx := context.Background()
			p, err := b.Prepare(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "authority" {
				if err := os.WriteFile(filepath.Join(f.dir, "policy.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				// Preserve original project for cleanup; a distinct same-root directory
				// cannot replay the retained in-memory plan even with identical bytes.
				if err := os.Rename(f.project, f.project+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.CopyFS(f.project, os.DirFS(f.project+"-original")); err != nil {
					t.Fatal(err)
				}
				err = filepath.WalkDir(f.project+"-original", func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					info, statErr := entry.Info()
					if statErr != nil {
						return statErr
					}
					rel, relErr := filepath.Rel(f.project+"-original", path)
					if relErr != nil {
						return relErr
					}
					return os.Chmod(filepath.Join(f.project, rel), info.Mode().Perm())
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := b.Recheck(ctx, p, p.Fingerprint()); err == nil {
				t.Fatal("authority/root replay accepted")
			}
		})
	}
}

func TestOutputAndObservationBounds(t *testing.T) {
	for _, files := range []map[string][]byte{
		{"../escape": nil}, {"A": nil, "a": nil}, {"a": nil, "a/b": nil}, {"a": nil, "A/b": nil}, {"a\\b": nil},
	} {
		if err := validateOutput(files); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("unsafe desired output accepted: %v", files)
		}
	}
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	large, err := os.Create(filepath.Join(root, "large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(maxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := observe(ctx, root); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unbounded read accepted: %v", err)
	}
}

func TestSignedNativeRegistryFingerprintAndGlobalJournal(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	var before, after state.Projects
	if err := yaml.Unmarshal(p.report.Registry.BeforeContent, &before); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(p.report.Registry.AfterContent, &after); err != nil {
		t.Fatal(err)
	}
	if len(before.Items) != 1 || len(after.Items) != 1 || before.Items[0].Template.Version != f.source.Commit || after.Items[0].Template.Version != f.target.Commit || before.Items[0].CreatedAt != after.Items[0].CreatedAt || before.Items[0].LastSeenAt != after.Items[0].LastSeenAt {
		t.Fatal("registry source/target or timestamp images differ")
	}
	// Exact same semantic registry with changed bytes is a stale plan too.
	raw := append(bytes.Clone(p.report.Registry.BeforeContent), []byte("\n# changed\n")...)
	if err := os.WriteFile(filepath.Join(b.home, "projects.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("registry drift accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(b.home, "projects.yaml"), p.report.Registry.BeforeContent, os.FileMode(p.report.Registry.Before.Mode)); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(b.home, "transactions/new/tx-blocker/active.json")
	if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prepare(ctx, in); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("global journal accepted: %v", err)
	}
}

func TestMergeBoundsBeforeAllocation(t *testing.T) {
	base := bytes.Repeat([]byte("line\n"), 2048)
	ours := append(bytes.Clone(base), []byte("ours")...)
	theirs := append(bytes.Clone(base), []byte("theirs")...)
	result, conflict := merge(base, ours, theirs)
	if !conflict || !bytes.Equal(result, ours) {
		t.Fatal("unbounded merge did not preserve ours")
	}
}

func TestSignedNativePlanRefusesIdenticalForeignReplacementAndRenderer(t *testing.T) {
	f, b, in := signedProject(t)
	ctx := context.Background()
	wrong, err := New(b.runtime, b.home, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Prepare(ctx, in); !errors.Is(err, operationtrust.ErrSourceAdapterUnsupported) {
		t.Fatalf("historical renderer mismatch accepted: %v", err)
	}
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.project, "hello.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	// Remove the preserved original from the project namespace so inode identity,
	// rather than an extra path or a byte/mode change, is the only difference.
	if err := os.Rename(path+".original", filepath.Join(f.dir, "retained-original")); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(ctx, p, p.Fingerprint()); !errors.Is(err, ErrStale) {
		t.Fatalf("identical foreign inode accepted: %v", err)
	}
}

func TestSignedNativePlanForeignNamespaceRefusal(t *testing.T) {
	cases := []struct {
		name      string
		target    map[string][]byte
		foreign   string
		directory bool
	}{
		{name: "file ancestor", target: map[string][]byte{"foreign/child.txt.tmpl": []byte("signed child")}, foreign: "foreign"},
		{name: "case folded file", target: map[string][]byte{"Foreign.txt.tmpl": []byte("signed target")}, foreign: "foreign.txt"},
		{name: "case folded directory", target: map[string][]byte{"Foreign/child.txt.tmpl": []byte("signed child")}, foreign: "foreign", directory: true},
		{name: "existing descendants", target: map[string][]byte{"foreign.tmpl": []byte("signed file")}, foreign: "foreign", directory: true},
		{name: "implicit target directory aliases", target: map[string][]byte{"New/one.txt.tmpl": []byte("one"), "new/two.txt.tmpl": []byte("two")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testfixture.RequireTrustStore(t)
			writer := func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
				return t5DWriteNativeSourceFiles(t, root, suffix, output, extra, tc.target)
			}
			fixture := t5DNewIntegrationFixtureWithSource(t, writer)
			f, b, in := materializeSignedProject(t, fixture)
			if tc.foreign != "" {
				name := filepath.Join(f.project, tc.foreign)
				if tc.directory {
					if err := os.Mkdir(name, 0o700); err != nil {
						t.Fatal(err)
					}
					name = filepath.Join(name, "user.txt")
				}
				if err := os.WriteFile(name, []byte("foreign-owned"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := observe(context.Background(), f.project)
			if err != nil {
				t.Fatal(err)
			}
			homeBefore, err := observe(context.Background(), b.home)
			if err != nil {
				t.Fatal(err)
			}
			p, err := b.Prepare(context.Background(), in)
			if err == nil {
				t.Fatalf("signed namespace collision accepted: %+v", p.report.Changes)
			}
			after, readErr := observe(context.Background(), f.project)
			if readErr != nil || !equalObservation(before, after) {
				t.Fatalf("foreign bytes/modes/inodes changed: %v", readErr)
			}
			homeAfter, readErr := observe(context.Background(), b.home)
			if readErr != nil || !equalObservation(homeBefore, homeAfter) {
				t.Fatalf("registry changed on refusal: %v", readErr)
			}
			t.Logf("SIGNED_NAMESPACE_REFUSAL: %v", err)
		})
	}
}

func TestSignedNativePlanResourceEditsNeverRelabeled(t *testing.T) {
	for _, kind := range []string{"independent line edit", "user deletion", "already signed target", "same-source local edit"} {
		t.Run(kind, func(t *testing.T) {
			f, b, in := signedProject(t)
			ctx := context.Background()
			resourcePath := ".tplaiter/generators/generators/entity.tmpl"
			full := filepath.Join(f.project, resourcePath)
			expected := []byte("snippet-source\nlocal\n")
			switch kind {
			case "user deletion":
				if err := os.Remove(full); err != nil {
					t.Fatal(err)
				}
			case "already signed target":
				expected = []byte("snippet-target\nstable\n")
				if err := os.WriteFile(full, expected, 0o644); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(full, expected, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "same-source local edit" {
				in.TargetInput = in.SourceInput
			}
			before, err := observe(ctx, f.project)
			if err != nil {
				t.Fatal(err)
			}
			p, err := b.Prepare(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range p.report.Changes {
				if c.Path != resourcePath {
					continue
				}
				found = true
				if kind == "already signed target" {
					if c.Conflict || !p.report.Publishable || !bytes.Equal(c.Content, expected) {
						t.Fatalf("exact signed image denied: %+v", c)
					}
				} else {
					if !c.Conflict || p.report.Publishable || c.Operation != "keep" {
						t.Fatalf("local resource relabeled as publishable: %+v", c)
					}
					if kind == "user deletion" {
						if c.After != nil {
							t.Fatal("deleted resource recreated")
						}
					} else if !bytes.Equal(c.Content, expected) {
						t.Fatalf("local resource bytes merged: %q", c.Content)
					}
				}
			}
			if !found {
				t.Fatal("missing resource decision")
			}
			if p.report.Publishable && !resourceChangesValid(p.report.Changes, mustTargetImages(t, b, in, p), p.report.Target) {
				t.Fatal("publishable resource images fail lock validation")
			}
			if kind != "already signed target" {
				if err := b.Apply(ctx, p, p.Fingerprint()); !errors.Is(err, ErrConflict) {
					t.Fatalf("resource conflict apply: %v", err)
				}
			}
			after, err := observe(ctx, f.project)
			if err != nil || !equalObservation(before, after) {
				t.Fatalf("resource preview wrote current bytes: %v", err)
			}
		})
	}
}

func mustTargetImages(t *testing.T, b *Backend, in Input, p *Plan) *resources.ResourceImages {
	t.Helper()
	images, err := b.sourceImages(context.Background(), in.TargetInput, p.report.Target)
	if err != nil {
		t.Fatal(err)
	}
	return images
}

func TestNamespaceIncludesImplicitAncestors(t *testing.T) {
	for _, target := range []map[string][]byte{
		{"New/one": nil, "new/two": nil}, {"New": nil, "new/two": nil}, {"new/one": nil, "New/one": nil},
	} {
		if err := validateOutput(target); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("target namespace aliases accepted: %v", target)
		}
	}
	observed := &observation{images: []Image{{Path: "foreign/user/file", Kind: "file"}}}
	if err := validateObservedNamespace(observed, map[string][]byte{"foreign": nil}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("observed descendants ignored: %v", err)
	}
	// Existing real directories may contain unrelated user files; creating a
	// distinct child does not claim ownership of that directory or sibling.
	if err := validateObservedNamespace(observed, map[string][]byte{"foreign/new": nil}); err != nil {
		t.Fatalf("unrelated foreign sibling rejected: %v", err)
	}
}
