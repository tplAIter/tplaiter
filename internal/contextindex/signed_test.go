package contextindex

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

	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

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
		if _, err = fmt.Fprintf(h, "%s:%s\n", strings.TrimPrefix(path, root), info.Mode()); err != nil {
			return err
		}
		if !info.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err = h.Write(b); err != nil {
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

func TestActualSignedRetrievalFreshPinsZeroWritesNoExecution(t *testing.T) {
	f := testfixture.NewGofmtFixture(t)
	runtime, resolution := f.Open(t)
	subject, refs := resolution.Subject(), resolution.Evidence()
	d := catalog(t)
	d.Sources[0].Anchor = provenance.RootSubject{Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.RequestedRef, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256, StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint, CheckpointCAS: refs.CheckpointCAS, InclusionProofCAS: refs.InclusionProofCAS}
	pin := &d.Sources[0].Pin
	pin.Origin = subject.Origin
	pin.TemplatePath = subject.TemplatePath
	pin.RequestedRef = subject.RequestedRef
	pin.Commit = subject.Commit
	pin.TreeDigest = subject.TreeSHA256
	pin.ContractDigest = subject.ContractSHA256
	if len(subject.Commit) == 64 {
		pin.CommitAlgorithm = "sha256"
	}
	snapshot, err := runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		t.Fatal(err)
	}
	d.Items = d.Items[2:]
	d.Items[0].Requires = []string{}
	d.Items[0].Produces = []string{}
	d.Edges = []knowledge.Edge{}
	for _, e := range snapshot.Entries() {
		if e.Path == "formatter/tool.json" {
			d.Items[0].SourcePath = e.Path
			d.Items[0].ContentSHA256 = e.ContentSHA256
			d.Items[0].Mode = e.Mode
		}
	}
	if d.Items[0].SourcePath != "formatter/tool.json" {
		t.Fatal("signed anchor missing")
	}
	// Position zero's declared evidence must not be used for the selected source.
	other := d.Sources[0]
	other.ID = "example:source:other"
	other.Pin.Alias = "other"
	other.Pin.Origin = "https://other.example.test/templates.git"
	other.Anchor.Origin = other.Pin.Origin
	other.Anchor.StatementCAS = "sha256:" + strings.Repeat("3", 64)
	d.Sources = append([]knowledge.Source{other}, d.Sources...)
	i := index(t, d)
	req := Request{Query: Query{ID: d.Items[0].ID, One: true}, MaxBytes: 32768}
	binding := Binding{SourceID: d.Items[0].SourceID, Runtime: runtime.TrustRuntime(), Resolution: resolution}
	root := filepath.Dir(f.Project())
	before := filesystemImage(t, root)
	metadata, err := i.Retrieve(context.Background(), req, []Binding{{SourceID: binding.SourceID}})
	if err != nil || len(metadata.Excerpts) != 0 || len(metadata.SourceEvidence) != 0 {
		t.Fatalf("metadata performed source operation: %v", err)
	}
	req.IncludeExcerpts = true
	req.MaxExcerptBytes = 2048
	p, err := i.Retrieve(context.Background(), req, []Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	blob, ok := snapshot.Blob(d.Items[0].SourcePath)
	if !ok {
		t.Fatal("blob missing")
	}
	want, err := boundedExcerpt(p.Records[0], blob, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Excerpts) != 1 || p.Excerpts[0].Content != want.Content || p.Excerpts[0].Digest != d.Items[0].ContentSHA256 || p.Bytes != len(wire(t, p)) {
		t.Fatal("excerpt or exact bound lost")
	}
	if len(p.SourceEvidence) != 1 || p.SourceEvidence[0].SourceID != binding.SourceID || p.SourceEvidence[0].StatementCAS != refs.StatementCAS || p.Records[0].State != "declared" {
		t.Fatal("source evidence misattributed or metadata upgraded")
	}
	// All failures preserve the same genuine fixture bytes/modes.
	for _, tc := range []struct {
		name, code string
		mutate     func(*knowledge.Catalog)
	}{
		{"missing", knowledge.SourceMissing, func(d *knowledge.Catalog) { d.Items[0].SourcePath = "missing.txt" }},
		{"stale digest", knowledge.SourceStale, func(d *knowledge.Catalog) { d.Items[0].ContentSHA256 = "sha256:" + strings.Repeat("2", 64) }},
		{"stale mode", knowledge.SourceStale, func(d *knowledge.Catalog) { d.Items[0].Mode = "100755" }},
		{"pin", knowledge.PinMismatch, func(d *knowledge.Catalog) { d.Sources[1].Anchor.SignatureCAS = "sha256:" + strings.Repeat("4", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := knowledge.Decode(wire(t, d))
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&bad)
			result, err := index(t, bad).Retrieve(context.Background(), req, []Binding{binding})
			var diagnostic *knowledge.Error
			if !errors.As(err, &diagnostic) || diagnostic.Code != tc.code || result.APIVersion != "" {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
			t.Logf("actual signed refusal: %s", diagnostic.Code)
		})
	}
	_, err = i.Retrieve(context.Background(), req, nil)
	outcome(t, err, Missing)
	_, err = i.Retrieve(context.Background(), req, []Binding{binding, binding})
	outcome(t, err, Ambiguous)
	_, err = i.Retrieve(context.Background(), Request{Query: req.Query, IncludeExcerpts: true, MaxBytes: metadata.Bytes}, []Binding{binding})
	outcome(t, err, Budget)
	second, _ := f.Open(t)
	foreign := binding
	foreign.Runtime = second.TrustRuntime()
	_, err = i.Retrieve(context.Background(), req, []Binding{foreign})
	var diagnostic *knowledge.Error
	if !errors.As(err, &diagnostic) || diagnostic.Code != knowledge.SourceMismatch {
		t.Fatalf("foreign runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = i.Retrieve(ctx, req, []Binding{binding})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if filesystemImage(t, root) != before {
		t.Fatal("retrieval or negative probes wrote bytes/modes")
	}
	entries, err := os.ReadDir(f.Scratch())
	if err != nil || len(entries) != 0 {
		t.Fatalf("fixture hook/tool executed: %v", err)
	}
	// The retained snapshot alone cannot authorize a new retrieval after tamper.
	f.CorruptSignedToolRecord(t)
	_, err = i.Retrieve(context.Background(), req, []Binding{binding})
	if err == nil {
		t.Fatal("retained snapshot bypassed fresh source verification")
	}
}
