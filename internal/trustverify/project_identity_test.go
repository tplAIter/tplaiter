package trustverify

import (
	"context"
	"errors"
	"testing"
)

func TestCheckProjectIdentityFreshOwner(t *testing.T) {
	f := newRuntimeFixture(t)
	f.project.RootPath = "/installed/project-a"
	r, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckProjectIdentity(context.Background(), f.project.RootPath, f.project.ProjectID); err != nil {
		t.Fatal(err)
	}
	for _, observation := range [][2]string{{"/installed/project-b", f.project.ProjectID}, {f.project.RootPath, "foreign-marker"}} {
		if err := r.CheckProjectIdentity(context.Background(), observation[0], observation[1]); err == nil {
			t.Fatal("foreign identity accepted")
		}
	}
	// A root replacement must fail even though profile binding digests do not
	// claim to bind installed roots or make source locks project-scoped.
	initial := f.project
	f.project.RootPath = "/installed/project-b"
	if err := r.CheckProjectIdentity(context.Background(), f.project.RootPath, f.project.ProjectID); err == nil {
		t.Fatal("reader root replacement accepted")
	}
	f.project = initial
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.CheckProjectIdentity(ctx, initial.RootPath, initial.ProjectID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if err := r.CheckProjectIdentity(nil, initial.RootPath, initial.ProjectID); err == nil { //nolint:staticcheck // Deliberately exercise nil-context denial.
		t.Fatal("nil context accepted")
	}
	if err := (*Runtime)(nil).CheckProjectIdentity(context.Background(), initial.RootPath, initial.ProjectID); err == nil {
		t.Fatal("nil runtime accepted")
	}
}

func TestCheckProjectIdentityRequiresRootProof(t *testing.T) {
	f := newRuntimeFixture(t) // old project-only reader has no installed root
	r, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckProjectIdentity(context.Background(), "/caller/root", f.project.ProjectID); err == nil {
		t.Fatal("missing installed root accepted")
	}
}
