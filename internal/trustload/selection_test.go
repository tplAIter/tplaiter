package trustload

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

func TestFiniteContextLookupAuthenticatesBeforeLookup(t *testing.T) {
	f := newLoadFixture(t)
	f.install.ProjectContexts = []ProjectContext{
		{Key: "a", ProjectID: "id-a", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(f.dir, "a")},
		{Key: "b", ProjectID: "id-b", SubmitterPrincipalID: "principal:operator", MinimumProfile: bootstrap.ProfileOSS, RootPath: filepath.Join(f.dir, "b")},
	}
	f.writeInstall(t)
	for _, want := range f.install.ProjectContexts {
		got, err := ResolveProjectContext(context.Background(), f.selection, want.Key)
		if err != nil || got != want {
			t.Fatalf("lookup: %+v %v", got, err)
		}
	}
	if _, err := ResolveProjectContext(context.Background(), f.selection, "unknown"); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("unknown: %v", err)
	}
	// RuntimeConfig pins semantic domain digest: JSON whitespace is harmless.
	raw := mustReadFile(t, f.installPath)
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.installPath, pretty, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProjectContext(context.Background(), f.selection, "a"); err != nil {
		t.Fatalf("semantic pin rejected whitespace: %v", err)
	}
	// Every nested FilePin remains a RAW-byte pin, even for unknown keys.
	for _, pin := range []FilePin{f.install.Descriptor, f.install.Provisioning, f.install.OperatorRecord, f.install.ExecutionPolicy} {
		original := mustReadFile(t, pin.Path)
		if err := os.WriteFile(pin.Path, append(append([]byte(nil), original...), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveProjectContext(context.Background(), f.selection, "unknown"); !errors.Is(err, ErrPinMismatch) {
			t.Fatalf("lookup bypassed raw %s pin: %v", filepath.Base(pin.Path), err)
		}
		if _, err := OpenRuntime(context.Background(), RuntimeOptions{Selection: f.selection, ProjectKey: "unknown", Clock: bootstrap.ClockFunc(time.Now)}); !errors.Is(err, ErrPinMismatch) {
			t.Fatalf("OpenRuntime looked up before full raw-pin authentication: %v", err)
		}
		if err := os.WriteFile(pin.Path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Replacing a root under an unchanged semantic pin never grants authority.
	f.install.ProjectContexts[0].RootPath = filepath.Join(f.dir, "foreign")
	changed, err := json.Marshal(f.install)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.installPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProjectContext(context.Background(), f.selection, "a"); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("context replacement: %v", err)
	}
}
