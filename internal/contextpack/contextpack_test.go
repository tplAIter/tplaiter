package contextpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

func graph(t *testing.T, root string) graphdoc.Document {
	t.Helper()
	body := []byte("package sample\nfunc Picked() {}\n")
	if err := os.WriteFile(filepath.Join(root, "sample.go"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	d := graphdoc.New()
	d.Nodes = []graphdoc.Node{{ID: "file", Kind: "file", Path: "sample.go", Line: 2, Provenance: []graphdoc.Provenance{{Source: "filesystem", Evidence: "sha256:" + hex.EncodeToString(sum[:]), Detected: true}}}, {ID: "decl", Kind: "declaration", Path: "sample.go", Line: 2}}
	d.Edges = []graphdoc.Edge{{From: "file", To: "decl", Kind: "declares"}}
	if err := d.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBuildHardSerializedLimitAndOmissions(t *testing.T) {
	d := graph(t, t.TempDir())
	p, err := Build(d, Request{MaxBytes: 32768, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != p.Bytes || len(raw) > HardLimit {
		t.Fatalf("advertised=%d actual=%d", p.Bytes, len(raw))
	}
	_, err = Build(d, Request{MaxBytes: 1})
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("want bounded error, got %v", err)
	}
	p, err = Build(d, Request{MaxBytes: 420, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(p)
	if len(raw) > 420 || p.Bytes != len(raw) {
		t.Fatalf("hard cap failed: %d/%d", p.Bytes, len(raw))
	}
	if p.OmittedNodes+p.OmittedRelations+p.OmittedSources == 0 {
		t.Fatal("expected constrained pack omissions")
	}
}

func TestVerifyBindsGraphAndRejectsSourceDrift(t *testing.T) {
	root := t.TempDir()
	d := graph(t, root)
	p, err := Build(d, Request{MaxBytes: HardLimit, Selected: []string{"file"}})
	if err != nil {
		t.Fatal(err)
	}
	ex, ok := excerpt(root, d.Nodes[1])
	if !ok {
		t.Fatal("fixture excerpt rejected")
	}
	p.Sources = []SourceExcerpt{ex}
	p.SourceDigests = []Digest{{Path: ex.Path, Digest: ex.Digest}}
	if err := Verify(d, root, p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sample.go"), []byte(strings.Repeat("x", 20)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(d, root, p); err == nil {
		t.Fatal("accepted drifted excerpt")
	}
}
