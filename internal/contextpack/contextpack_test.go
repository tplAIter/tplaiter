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
	reader, err := newSourceReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.close()
	ex, ok := excerpt(reader, d.Nodes[1])
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

func sourceGraph(t *testing.T, root, rel string, body []byte, line int) graphdoc.Document {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	d := graphdoc.New()
	d.Nodes = []graphdoc.Node{{
		ID:   "source",
		Kind: "file",
		Path: rel,
		Line: line,
		Provenance: []graphdoc.Provenance{{
			Source: "filesystem", Evidence: "sha256:" + hex.EncodeToString(sum[:]), Detected: true,
		}},
	}}
	if err := d.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBuildRejectsKnownHashOutsideParentSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	body := []byte("outside secret\n")
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	d := sourceGraph(t, root, "link/secret.go", body, 1)
	p, err := Build(d, Request{Root: root, MaxBytes: HardLimit, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sources) != 0 || len(p.SourceDigests) != 0 {
		t.Fatal("included source through an outside-parent symlink")
	}
}

func TestBuildClampsLargeAnchorAndRejectsOversizedKnownHash(t *testing.T) {
	root := t.TempDir()
	body := []byte("one\ntwo\nthree\n")
	d := sourceGraph(t, root, "inside.go", body, int(^uint(0)>>1))
	p, err := Build(d, Request{Root: root, MaxBytes: HardLimit, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sources) != 1 || p.Sources[0].Start < 1 || p.Sources[0].End > 4 {
		t.Fatalf("large anchor was not safely clamped: %+v", p.Sources)
	}

	large := strings.Repeat("x", reasonableMaxSourceBytes+1)
	largeDoc := sourceGraph(t, root, "oversized.go", []byte(large), 1)
	p, err = Build(largeDoc, Request{Root: root, MaxBytes: HardLimit, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sources) != 0 {
		t.Fatal("included an oversized source with a matching known hash")
	}
}

func TestBuildAndVerifyPreserveBoundedAccountingAndDetectSourceDrift(t *testing.T) {
	root := t.TempDir()
	body := []byte("package sample\nfunc Picked() {}\n")
	d := sourceGraph(t, root, "sample.go", body, 2)
	p, err := Build(d, Request{Root: root, MaxBytes: DefaultLimit, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != p.Bytes || p.Bytes > DefaultLimit || p.TokenEstimate != (p.Bytes+3)/4 {
		t.Fatalf("invalid bounded accounting: bytes=%d raw=%d tokens=%d", p.Bytes, len(raw), p.TokenEstimate)
	}
	if len(p.Sources) == 0 {
		t.Fatal("expected source in bounded pack")
	}
	if err := Verify(d, root, p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sample.go"), []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(d, root, p); err == nil {
		t.Fatal("accepted source drift")
	}
}

func TestSourceReaderUnsupportedDiagnosticIsNarrow(t *testing.T) {
	if got := sourceReaderUnsupportedDiagnostic(unsupportedSourceReadingError{platform: "test"}); got != "contextpack: source reading unavailable on unsupported platform: test" {
		t.Fatalf("unexpected unsupported-platform diagnostic: %q", got)
	}
	if got := sourceReaderUnsupportedDiagnostic(errors.New("ordinary source unavailable")); got != "" {
		t.Fatalf("ordinary source error disclosed as unsupported platform: %q", got)
	}
}

func TestBuildDoesNotDiscloseOrdinarySourceUnavailable(t *testing.T) {
	root := t.TempDir()
	d := graph(t, root)
	missing := filepath.Join(t.TempDir(), "missing")
	withSource, err := Build(d, Request{Root: missing, MaxBytes: HardLimit, IncludeSource: true})
	if err != nil {
		t.Fatal(err)
	}
	withoutSource, err := Build(d, Request{Root: missing, MaxBytes: HardLimit})
	if err != nil {
		t.Fatal(err)
	}
	if len(withSource.Diagnostics) != 0 || len(withoutSource.Diagnostics) != 0 {
		t.Fatalf("ordinary unavailable source path disclosed diagnostics: with=%v without=%v", withSource.Diagnostics, withoutSource.Diagnostics)
	}
}

func TestUnsupportedSourceDiagnosticRequiresBudget(t *testing.T) {
	root := t.TempDir()
	d := graph(t, root)
	factory := func(string) (sourceReader, error) {
		return nil, unsupportedSourceReadingError{platform: "test"}
	}
	_, err := buildWithSourceReader(d, Request{MaxBytes: 300, IncludeSource: true}, factory)
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("unsupported diagnostic over budget returned %v", err)
	}
	p, err := buildWithSourceReader(d, Request{MaxBytes: HardLimit, IncludeSource: true}, factory)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Diagnostics) != 1 || p.Diagnostics[0] != "contextpack: source reading unavailable on unsupported platform: test" {
		t.Fatalf("unsupported diagnostic was not retained: %v", p.Diagnostics)
	}
}
