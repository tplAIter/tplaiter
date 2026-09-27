package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeBaselineAndSave(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}

	hashes, err := ComputeBaseline(dir, []string{"a.txt", "sub/b.txt"})
	if err != nil {
		t.Fatalf("ComputeBaseline: %v", err)
	}
	if len(hashes) != 2 || hashes["a.txt"] == "" || hashes["sub/b.txt"] == "" {
		t.Fatalf("unexpected hashes: %+v", hashes)
	}
	if hashes["a.txt"] == hashes["sub/b.txt"] {
		t.Error("different content should hash differently")
	}

	baseline := &Baseline{Schema: BaselineSchema, TemplateVersion: "0.1.0", ContextHash: "deadbeef", Files: hashes}
	if err := baseline.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(BaselineRelPath)))
	if err != nil {
		t.Fatalf("read saved baseline: %v", err)
	}
	var got Baseline
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal saved baseline: %v", err)
	}
	if got.Schema != BaselineSchema || got.TemplateVersion != "0.1.0" || got.ContextHash != "deadbeef" {
		t.Errorf("round-tripped baseline mismatch: %+v", got)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("expected baseline.json to end with a trailing newline")
	}
}

func TestHashContextDeterministic(t *testing.T) {
	ctx1 := NewContext(testOptions())
	ctx2 := NewContext(testOptions())

	h1, err := hashContext(ctx1)
	if err != nil {
		t.Fatalf("hashContext: %v", err)
	}
	h2, err := hashContext(ctx2)
	if err != nil {
		t.Fatalf("hashContext: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hashContext not stable across equal contexts: %q != %q", h1, h2)
	}

	opts := testOptions()
	opts.Runtime.Port = 9090
	h3, err := hashContext(NewContext(opts))
	if err != nil {
		t.Fatalf("hashContext: %v", err)
	}
	if h1 == h3 {
		t.Error("hashContext should change when Runtime.Port changes")
	}
}
