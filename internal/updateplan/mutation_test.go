package updateplan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestSignedMutationExactImages(t *testing.T) {
	writer := func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
		return t5DWriteNativeSourceFiles(t, root, suffix, output, extra, map[string][]byte{"fresh/nested/empty.txt.tmpl": {}})
	}
	f, b, in := materializeSignedProject(t, t5DNewIntegrationFixtureWithSource(t, writer))
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(f.project, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "hello.txt"), []byte("hello source\nlocal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := observe(ctx, f.project)
	if err != nil {
		t.Fatal(err)
	}
	homeBefore, err := observe(ctx, b.home)
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Prepare(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.prepareMutation(ctx, p, p.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if m.plan == p || m.plan.report.Source != p.report.Source || m.plan.report.Target != p.report.Target || !equalObservation(before, m.plan.observed) {
		t.Fatal("mutation did not retain fresh signed bindings and complete read set")
	}
	found := map[string]mutationImage{}
	for _, c := range m.changes {
		found[c.path] = c
		if c.path == "foreign.txt" || c.path == ".tplaiter" {
			t.Fatalf("foreign file or existing directory in write set: %s", c.path)
		}
	}
	hello := found["hello.txt"]
	if hello.before == nil || hello.after == nil || !bytes.Equal(hello.before.data, []byte("hello source\nlocal\n")) || !bytes.Equal(hello.after.data, []byte("hello target\nlocal\n")) {
		t.Fatal("exact current preimage or permitted ordinary merge lost")
	}
	for _, parent := range []string{"fresh", "fresh/nested"} {
		c := found[parent]
		if c.before != nil || c.after == nil || c.after.image.Kind != "directory" || c.after.image.Mode != 0o755 {
			t.Fatalf("missing explicit new directory image %s", parent)
		}
	}
	empty := found["fresh/nested/empty.txt"]
	if empty.before != nil || empty.after == nil || empty.after.image.Kind != "file" || empty.after.image.SHA256 != evidencecas.Digest(nil) || len(empty.after.data) != 0 {
		t.Fatal("empty file confused with absence")
	}
	resource := found[".tplaiter/generators/generators/entity.tmpl"]
	if resource.after == nil || !bytes.Equal(resource.after.data, []byte("snippet-target\nstable\n")) {
		t.Fatal("resource afterimage is not exact verified target")
	}
	if m.registry.Before != p.report.Registry.Before || m.registry.After != p.report.Registry.After || !bytes.Equal(m.registry.BeforeContent, p.report.Registry.BeforeContent) || !bytes.Equal(m.registry.AfterContent, p.report.Registry.AfterContent) {
		t.Fatal("registry exact images lost")
	}
	// Mutating private bridge candidates must not mutate their fresh proof or
	// original plan. They are copied observations, not additional authority.
	hello.after.data[0] ^= 1
	m.registry.AfterContent[0] ^= 1
	for _, c := range m.plan.report.Changes {
		if c.Path == "hello.txt" && !bytes.Equal(c.Content, []byte("hello target\nlocal\n")) {
			t.Fatal("mutable afterimage aliased proof")
		}
	}
	if !bytes.Equal(m.plan.report.Registry.AfterContent, p.report.Registry.AfterContent) {
		t.Fatal("mutable registry image aliased proof")
	}
	after, err := observe(ctx, f.project)
	if err != nil || !equalObservation(before, after) {
		t.Fatalf("boundary wrote project: %v", err)
	}
	homeAfter, err := observe(ctx, b.home)
	if err != nil || !equalObservation(homeBefore, homeAfter) {
		t.Fatalf("boundary wrote registry: %v", err)
	}
}

func TestSignedMutationRefusesDriftAndConflict(t *testing.T) {
	for _, kind := range []string{"fingerprint", "detached report", "foreign creation", "inode replacement", "resource edit", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, b, in := signedProject(t)
			ctx := context.Background()
			p, err := b.Prepare(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			expected := p.Fingerprint()
			want := ErrStale
			switch kind {
			case "fingerprint":
				expected = "sha256:foreign"
				want = ErrInvalid
			case "detached report":
				p.report.Publishable = false
				want = ErrInvalid
			case "foreign creation":
				if err := os.WriteFile(filepath.Join(f.project, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "inode replacement":
				name := filepath.Join(f.project, "hello.txt")
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, raw, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(name + ".old"); err != nil {
					t.Fatal(err)
				}
			case "resource edit":
				if err := os.WriteFile(filepath.Join(f.project, ".tplaiter/generators/generators/entity.tmpl"), []byte("snippet-source\nlocal\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				p, err = b.Prepare(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				expected = p.Fingerprint()
				want = ErrConflict
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			before, err := observe(context.Background(), f.project)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.prepareMutation(ctx, p, expected); !errors.Is(err, want) {
				t.Fatalf("%s: %v, want %v", kind, err, want)
			}
			after, err := observe(context.Background(), f.project)
			if err != nil || !equalObservation(before, after) {
				t.Fatalf("refusal wrote project: %v", err)
			}
		})
	}
}

func TestMutationDeletionRetainsExactPreimage(t *testing.T) {
	raw := []byte("user-owned prior bytes")
	image := Image{Path: "obsolete", Kind: "file", Mode: 0o600, SHA256: evidencecas.Digest(raw)}
	p := &Plan{observed: &observation{images: []Image{image}, files: map[string][]byte{"obsolete": raw}}, report: Report{Changes: []Change{{Path: "obsolete", Before: &image, Operation: "delete"}}}}
	m, err := buildMutation(p)
	if err != nil || len(m.changes) != 1 || m.changes[0].after != nil || m.changes[0].before == nil || m.changes[0].before.image != image || !bytes.Equal(m.changes[0].before.data, raw) {
		t.Fatalf("deletion lost exact preimage: %v", err)
	}
}
