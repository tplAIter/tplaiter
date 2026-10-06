package trustload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func TestRuntimeOwnedReadonlyEvidenceLifetime(t *testing.T) {
	fixture := runtimeFixture(t)
	for ref, raw := range fixture.evidence {
		hex := ref[len("sha256:"):]
		path := filepath.Join(fixture.load.install.EvidenceRoot, "sha256", hex[:2], hex[2:])
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := OpenRuntime(context.Background(), RuntimeOptions{Selection: fixture.selection, ProjectKey: "project", Clock: fixedRuntimeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for ref, want := range fixture.evidence {
		got, err := r.Read(context.Background(), ref)
		if err != nil || !bytes.Equal(got, want) || evidencecas.Digest(got) != ref {
			t.Fatalf("owned reader: %s %v", ref, err)
		}
	}
	// Corrupting a raw lifecycle object must not fall back to the
	// authenticated store's still-valid copy.
	for ref := range fixture.evidence {
		hex := ref[len("sha256:"):]
		path := filepath.Join(fixture.load.install.EvidenceRoot, "sha256", hex[:2], hex[2:])
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("tampered public test evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(context.Background(), ref); err == nil {
			t.Fatal("corrupt lifecycle CAS fell back to trust-store evidence")
		}
		break
	}
	// Deleting a lifecycle object must preserve the missing-object cause,
	// even when the bootstrap trust store contains identical bytes.
	for ref := range fixture.evidence {
		hex := ref[len("sha256:"):]
		path := filepath.Join(fixture.load.install.EvidenceRoot, "sha256", hex[:2], hex[2:])
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(context.Background(), ref); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing lifecycle object fallback: %v", err)
		}
		break
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Read(ctx, "invalid"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for ref := range fixture.evidence {
		if _, err := r.Read(context.Background(), ref); !errors.Is(err, ErrProvenanceUnavailable) {
			t.Fatalf("reader survived close: %v", err)
		}
		break
	}
	if _, err := (*Runtime)(nil).Read(context.Background(), "anything"); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatal(err)
	}
}

func TestRuntimeReadBoundedLifetimeAndCap(t *testing.T) {
	fixture := runtimeFixture(t)
	for ref, raw := range fixture.evidence {
		hex := ref[len("sha256:"):]
		path := filepath.Join(fixture.load.install.EvidenceRoot, "sha256", hex[:2], hex[2:])
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := OpenRuntime(context.Background(), RuntimeOptions{Selection: fixture.selection, ProjectKey: "project", Clock: fixedRuntimeClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var ref string
	var want []byte
	for ref, want = range fixture.evidence {
		break
	}
	got, err := r.ReadBounded(context.Background(), ref, int64(len(want)))
	if err != nil || !bytes.Equal(got, want) || cap(got) != len(got) {
		t.Fatalf("runtime bounded copy: %v", err)
	}
	if _, err := r.ReadBounded(context.Background(), ref, int64(len(want)-1)); !errors.Is(err, evidencecas.ErrBoundExceeded) {
		t.Fatal(err)
	}
	if len(got) > 0 {
		got[0] ^= 0xff
	}
	again, err := r.ReadBounded(context.Background(), ref, int64(len(want)))
	if err != nil || !bytes.Equal(again, want) {
		t.Fatalf("caller copy changed evidence: %v", err)
	}
	// Cancellation while waiting for the runtime lifetime mutex must precede IO.
	baseContext, cancel := context.WithCancel(context.Background())
	ctx := &boundedEntryContext{Context: baseContext, checked: make(chan struct{}, 1)}
	r.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := r.ReadBounded(ctx, ref, int64(len(want))); done <- err }()
	select {
	case <-ctx.checked:
	case <-time.After(2 * time.Second):
		r.mu.Unlock()
		t.Fatal("reader did not enter")
	}
	cancel()
	r.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded canceled call stalled")
	}
	if _, err := r.ReadBounded(nil, ref, 1); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadBounded(context.Background(), ref, 1); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatal(err)
	}
	if _, err := (*Runtime)(nil).ReadBounded(context.Background(), ref, 1); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatal(err)
	}
}

// Capture the first successful preflight check before signaling the test, so
// cancellation necessarily occurs after it and before acquiring the held mutex.
type boundedEntryContext struct {
	context.Context
	checked chan struct{}
}

func (c *boundedEntryContext) Err() error {
	err := c.Context.Err()
	select {
	case c.checked <- struct{}{}:
	default:
	}
	return err
}
