package semanticgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeReportsSyntaxFactsWithoutCalls(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(1) }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := Analyze(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest == "" {
		t.Fatal("missing digest")
	}
	for _, e := range d.Edges {
		if e.Kind == "resolved-call" || e.Kind == "calls" {
			t.Fatalf("fabricated call edge: %#v", e)
		}
	}
}

func TestAnalyzeRustVisibilityAndModifiers(t *testing.T) {
	root := t.TempDir()
	src := "pub fn public() {}\npub async fn asynchronous() {}\npub unsafe fn dangerous() {}\nfn plain() {}\nfn\n"
	if err := os.WriteFile(filepath.Join(root, "lib.rs"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := Analyze(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"public": false, "asynchronous": false, "dangerous": false, "plain": false}
	for _, n := range d.Nodes {
		if _, ok := want[n.Name]; ok {
			want[n.Name] = true
		}
	}
	for n, ok := range want {
		if !ok {
			t.Fatalf("missing Rust declaration %q: %#v", n, d.Nodes)
		}
	}
}
