package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

// Observe every fixture file's bytes/mode before calling the read-only bridge.
// The signed executable in the fixture is data; scratch must stay empty.
func filesystemImage(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(h, "%s:%s\n", strings.TrimPrefix(path, root), info.Mode()); err != nil {
			return err
		}
		if !info.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := h.Write(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestActualSignedSnapshotObservationZeroWritesNoExecution(t *testing.T) {
	f := testfixture.NewGofmtFixture(t)
	runtime, resolution := f.Open(t)
	subject, refs := resolution.Subject(), resolution.Evidence()
	d, _ := fixture(t)
	d.Sources[0].Anchor = provenance.RootSubject{Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.RequestedRef, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256, StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint, CheckpointCAS: refs.CheckpointCAS, InclusionProofCAS: refs.InclusionProofCAS}
	p := &d.Sources[0].Pin
	p.Origin = subject.Origin
	p.TemplatePath = subject.TemplatePath
	p.RequestedRef = subject.RequestedRef
	p.Commit = subject.Commit
	p.TreeDigest = subject.TreeSHA256
	p.ContractDigest = subject.ContractSHA256
	if len(subject.Commit) == 64 {
		p.CommitAlgorithm = "sha256"
	}
	snapshot, err := runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		t.Fatal(err)
	}
	d.Items = d.Items[2:]
	it := &d.Items[0]
	it.Requires = []string{}
	it.Produces = []string{}
	d.Edges = []Edge{}
	for _, e := range snapshot.Entries() {
		if e.Path == "formatter/tool.json" {
			it.SourcePath = e.Path
			it.ContentSHA256 = e.ContentSHA256
			it.Mode = e.Mode
		}
	}
	if it.SourcePath != "formatter/tool.json" {
		t.Fatal("actual source record absent")
	}
	// An extra declared source verifies that the selected source's evidence,
	// rather than position zero's proof, is used in the authenticated projection.
	other := d.Sources[0]
	other.ID = "example:source:other"
	other.Pin.Alias = "other"
	other.Pin.Origin = "https://other.example.test/templates.git"
	other.Anchor.Origin = other.Pin.Origin
	other.Anchor.StatementCAS = "sha256:" + strings.Repeat("3", 64)
	other.Pin.Commit = strings.Repeat("b", 40)
	other.Anchor.Commit = other.Pin.Commit
	other.Pin.CommitAlgorithm = "sha1"
	d.Sources = append([]Source{other}, d.Sources...)
	raw := wire(t, d)
	root := filepath.Dir(f.Project())
	before := filesystemImage(t, root)
	observed, err := ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, raw, it.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	} // Observation owns immutable descriptor bytes.
	g, err := observed.Graph()
	if err != nil {
		t.Fatal(err)
	}
	if err := graphdoc.Verify(g); err != nil {
		t.Fatal(err)
	}
	for _, n := range g.Nodes {
		if n.ID == it.ID {
			if n.Attributes["sourceEvidenceState"] != "authenticated" || n.Attributes["evidenceState"] != "declared" {
				t.Fatal("authentication scope lost")
			}
			found := false
			for _, p := range n.Provenance {
				if p.Detected && p.Evidence == refs.StatementCAS {
					found = true
				}
			}
			if !found {
				t.Fatal("wrong selected source evidence")
			}
		}
		if n.ID == other.ID && n.Attributes["sourceEvidenceState"] != "" {
			t.Fatal("unselected source falsely authenticated")
		}
	}
	if filesystemImage(t, root) != before {
		t.Fatal("observation wrote fixture bytes/modes")
	}
	entries, err := os.ReadDir(f.Scratch())
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected execution: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ObserveSource(ctx, runtime.TrustRuntime(), resolution, wire(t, d), it.SourceID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	bad := d
	bad.Items = append([]Item(nil), d.Items...)
	bad.Items[0].ContentSHA256 = "sha256:" + strings.Repeat("2", 64)
	_, err = ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, wire(t, bad), it.SourceID)
	assertAnchorOutcome(t, err, SourceStale, it.ID)
	bad.Items[0] = d.Items[0]
	bad.Items[0].Mode = "100755"
	_, err = ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, wire(t, bad), it.SourceID)
	assertAnchorOutcome(t, err, SourceStale, it.ID)
	bad.Items[0] = d.Items[0]
	bad.Items[0].SourcePath = "foreign.txt"
	_, err = ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, wire(t, bad), it.SourceID)
	assertAnchorOutcome(t, err, SourceMissing, it.ID)
	bad = d
	bad.Sources = append([]Source(nil), d.Sources...)
	bad.Sources[1].Anchor.SignatureCAS = "sha256:" + strings.Repeat("4", 64)
	_, err = ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, wire(t, bad), it.SourceID)
	assertAnchorOutcome(t, err, PinMismatch, it.SourceID)
	if filesystemImage(t, root) != before {
		t.Fatal("negative probes wrote fixture bytes/modes")
	}
	// A different concrete runtime cannot reuse this opaque resolution.
	second, _ := f.Open(t)
	_, err = ObserveSource(context.Background(), second.TrustRuntime(), resolution, wire(t, d), it.SourceID)
	assertCode(t, err, SourceMismatch)
	f.CorruptSignedToolRecord(t)
	_, err = ObserveSource(context.Background(), runtime.TrustRuntime(), resolution, wire(t, d), it.SourceID)
	if err == nil {
		t.Fatal("stale retained resolution bypassed actual source tamper")
	}
}

func TestForgedObservationAndSourcePinStayData(t *testing.T) {
	var o Observation
	_, err := o.Graph()
	assertCode(t, err, SourceMismatch)
	d, _ := fixture(t)
	raw := wire(t, d)
	_, err = ObserveSource(context.Background(), nil, nil, raw, d.Sources[0].ID)
	assertCode(t, err, SourceMismatch)
	// Complete structurally valid pin data is not an authenticated resolution.
	if _, err := deps.DecodePinnedSource(wire(t, d.Sources[0].Pin)); err != nil {
		t.Fatal(err)
	}
}

func assertAnchorOutcome(t *testing.T, err error, code, id string) {
	t.Helper()
	assertCode(t, err, code)
	var diagnostic *Error
	if !errors.As(err, &diagnostic) || diagnostic.Path != id {
		t.Fatalf("semantic outcome lost exact identity: %v", err)
	}
	t.Logf("actual signed outcome: %s at %s", diagnostic.Code, diagnostic.Path)
}
