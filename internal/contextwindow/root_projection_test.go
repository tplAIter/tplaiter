package contextwindow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

func rootSignedProjection(t *testing.T) (*Selection, *testfixture.Fixture) {
	t.Helper()
	f := testfixture.NewGofmtFixture(t)
	runtime, resolution := f.Open(t)
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	d, e := knowledge.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	sub, refs := resolution.Subject(), resolution.Evidence()
	d.Sources = d.Sources[:1]
	s := &d.Sources[0]
	s.ID = "root:source:installed"
	s.Anchor = provenance.RootSubject{Origin: sub.Origin, TemplatePath: sub.TemplatePath, RequestedRef: sub.RequestedRef, Commit: sub.Commit, TreeSHA256: sub.TreeSHA256, ContractSHA256: sub.ContractSHA256, StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint, CheckpointCAS: refs.CheckpointCAS, InclusionProofCAS: refs.InclusionProofCAS}
	s.Pin.Origin = sub.Origin
	s.Pin.TemplatePath = sub.TemplatePath
	s.Pin.RequestedRef = sub.RequestedRef
	s.Pin.Commit = sub.Commit
	s.Pin.TreeDigest = sub.TreeSHA256
	s.Pin.ContractDigest = sub.ContractSHA256
	if len(sub.Commit) == 64 {
		s.Pin.CommitAlgorithm = "sha256"
	}
	snapshot, e := runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if e != nil {
		t.Fatal(e)
	}
	d.Items = d.Items[2:]
	it := &d.Items[0]
	it.ID = "root:resource:r-" + strings.Repeat("a", 32)
	it.SourceID = s.ID
	it.Requires = []string{}
	it.Produces = []string{}
	d.Edges = []knowledge.Edge{}
	blob, ok := snapshot.Blob("formatter/tool.json")
	if !ok {
		t.Fatal("source fixture blob")
	}
	it.SourcePath = "formatter/tool.json"
	it.ContentSHA256 = evidencecas.Digest(blob)
	it.Mode = "100644"
	idx, e := contextindex.New(encoded(t, d), nil)
	if e != nil {
		t.Fatal(e)
	}
	req := contextindex.Request{Query: contextindex.Query{ID: it.ID, One: true}, MaxBytes: 32768, IncludeExcerpts: true, MaxExcerptBytes: 2048}
	selected, e := Select(context.Background(), idx, req, []contextindex.Binding{{SourceID: s.ID, Runtime: runtime.TrustRuntime(), Resolution: resolution}})
	if e != nil {
		t.Fatal(e)
	}
	return selected, f
}
func TestRootProjectionAuthenticatedOwnedAndLegacyWire(t *testing.T) {
	original, _ := rootSignedProjection(t)
	ctx := context.Background()
	projected, e := FactorRootSelectionV2(ctx, original)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original.raw, projected.raw) || projected.index != original.index || projected.bindings[0].Resolution != original.bindings[0].Resolution || projected.query != original.query {
		t.Fatal("projection replaced authority or logical bytes")
	}
	p, e := contextindex.DecodeRootFactsV2(projected.deliveryBytes())
	if e != nil || !bytes.Equal(encoded(t, p), original.raw) {
		t.Fatal("projection lost complete packet", e)
	}
	legacyAdapter, _ := NewByteAdapter(Scope{Session: "legacy", Model: "unknown"}, baseEnvelope())
	h := legacyAdapter.Host()
	defer h.Revoke()
	req := Request{ID: "legacy", Selection: original, MaxBytes: 32768, OutputByteReserve: 64}
	held, plan, e := h.Reserve(ctx, observation(t, h), req)
	if e != nil {
		t.Fatal(e)
	}
	expected := encoded(t, struct {
		Query, Selection  string
		Optional          []Optional
		MaxBytes          int
		Reasoning, Output int64
		OutputBytes       int
	}{original.query, digest(original.raw), nil, 32768, 0, 0, 64})
	if held.fingerprint != digest(expected) {
		t.Fatal("legacy fingerprint changed")
	}
	var wire struct {
		Parallel []struct {
			Context struct {
				Required json.RawMessage `json:"required"`
			} `json:"context"`
		} `json:"parallel"`
	}
	if e = json.Unmarshal(plan.Envelope, &wire); e != nil || !bytes.Equal(wire.Parallel[0].Context.Required, original.raw) {
		t.Fatal("legacy wire changed", e)
	}
	freshAdapter, _ := NewByteAdapter(Scope{Session: "v2", Model: "unknown"}, baseEnvelope())
	host := freshAdapter.Host()
	defer host.Revoke()
	v2held, v2plan, e := host.Reserve(ctx, observation(t, host), Request{ID: "v2", Selection: projected, MaxBytes: 32768, OutputByteReserve: 64})
	if e != nil {
		t.Fatal(e)
	}
	if v2held.fingerprint == held.fingerprint || !bytes.Contains(v2plan.Envelope, []byte(contextindex.RootFactsAPIVersion)) {
		t.Fatal("projection identity not bound")
	}
	receipt, e := freshAdapter.Deliver(ctx, v2held, exchangeFunc(func(ctx context.Context, raw []byte, max int) ([]byte, error) {
		if !bytes.Equal(raw, v2plan.Envelope) || max != 64 {
			t.Fatal("unmeasured bytes")
		}
		return []byte("complete packet consumed"), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	if e = host.Finish(ctx, v2held, receipt); e != nil {
		t.Fatal(e)
	}
	t.Log("actual source-bound C03 carrier retained; ROOT projection reconstructs full packet; legacy wire/fingerprint exact; real C04 Reserve/Deliver/Finish")
}
func TestRootProjectionRejectsMetadataForgedBytesAndCancellation(t *testing.T) {
	s, _ := rootSignedProjection(t)
	metadataReq := s.request
	metadataReq.IncludeExcerpts = false
	metadata, e := Select(context.Background(), s.index, metadataReq, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = FactorRootSelectionV2(context.Background(), metadata); e == nil {
		t.Fatal("metadata minted projection authority")
	}
	p, e := FactorRootSelectionV2(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	p.wire[0] = '!'
	if e = selectionFresh(context.Background(), p); e == nil {
		t.Fatal("changed wire survived freshness")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = FactorRootSelectionV2(ctx, s); e == nil {
		t.Fatal("cancel ignored")
	}
	original := append([]byte(nil), s.raw...)
	s.raw[0] = '!'
	if _, e = FactorRootSelectionV2(context.Background(), s); e == nil {
		t.Fatal("replacement logical packet accepted")
	}
	s.raw = original
}
