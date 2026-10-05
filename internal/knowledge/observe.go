package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// Observation is an immutable read-only observation of exact source anchors and
// item bytes. It is neither an execution permit nor authenticated ownership.
type Observation struct {
	raw      []byte
	sourceID string
}

// ObserveSource reauthenticates the opaque resolution before and after checking
// retained snapshot bytes. It opens no descriptor paths and executes no tools.
// Other sources, semantic edges, provider labels and quality claims stay data.
func ObserveSource(ctx context.Context, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, raw []byte, sourceID string) (*Observation, error) {
	if ctx == nil || runtime == nil || !resolution.ValidFor(runtime, runtime.Binding()) {
		return nil, fail(SourceMismatch, "runtime resolution")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Own input bytes before any external reads; callers cannot change the
	// descriptor between validation and the authenticated observation.
	owned := append([]byte(nil), raw...)
	d, err := Decode(owned)
	if err != nil {
		return nil, err
	}
	var source *Source
	for i := range d.Sources {
		if d.Sources[i].ID == sourceID {
			source = &d.Sources[i]
			break
		}
	}
	if source == nil {
		return nil, fail(SourceMissing, "sourceId")
	}
	a := source.Anchor
	refs := resolution.Evidence()
	expected := trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: a.StatementCAS, SignatureCAS: a.SignatureCAS, KeyFingerprint: a.KeyFingerprint, CheckpointCAS: a.CheckpointCAS, InclusionProofCAS: a.InclusionProofCAS}
	if a.Subject() != resolution.Subject() {
		return nil, fail(SourceStale, sourceID)
	}
	if expected != refs {
		return nil, fail(PinMismatch, sourceID)
	}
	fresh, err := runtime.VerifySubject(ctx, resolution.Subject(), refs)
	if err != nil {
		return nil, fmt.Errorf("knowledge: authenticate source: %w", err)
	}
	snapshot, err := runtime.VerifiedSnapshot(fresh)
	if err != nil {
		return nil, fmt.Errorf("knowledge: retained source: %w", err)
	}
	entries := map[string]trustverify.SourceEntry{}
	for _, e := range snapshot.Entries() {
		entries[e.Path] = e
	}
	count := 0
	for _, it := range d.Items {
		if it.SourceID != sourceID {
			continue
		}
		count++
		e, ok := entries[it.SourcePath]
		blob, present := snapshot.Blob(it.SourcePath)
		if !ok {
			return nil, fail(SourceMissing, it.ID)
		}
		if e.Kind != "file" || e.Mode != it.Mode {
			return nil, fail(SourceStale, it.ID)
		}
		if !present {
			return nil, fail(SourceMissing, it.ID)
		}
		h := sha256.Sum256(blob)
		if e.ContentSHA256 != it.ContentSHA256 || "sha256:"+hex.EncodeToString(h[:]) != it.ContentSHA256 {
			return nil, fail(SourceStale, it.ID)
		}
	}
	if count == 0 {
		return nil, fail(SourceMismatch, "no anchored items")
	}
	if _, err := runtime.VerifySubject(ctx, fresh.Subject(), fresh.Evidence()); err != nil {
		return nil, fmt.Errorf("knowledge: confirm source: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Observation{raw: owned, sourceID: sourceID}, nil
}

// Graph projects this observation without elevating descriptor-owned metadata.
// Detected means exact source content observed; evidenceScope states its bounds.
func (o *Observation) Graph() (graphdoc.Document, error) {
	if o == nil || o.sourceID == "" {
		return graphdoc.Document{}, fail(SourceMismatch, "observation")
	}
	d, err := Decode(o.raw)
	if err != nil {
		return graphdoc.Document{}, err
	}
	g, err := Project(d)
	if err != nil {
		return graphdoc.Document{}, err
	}
	evidence := ""
	for _, s := range d.Sources {
		if s.ID == o.sourceID {
			evidence = s.Anchor.StatementCAS
		}
	}
	ids := map[string]bool{o.sourceID: true}
	for _, it := range d.Items {
		if it.SourceID == o.sourceID {
			ids[it.ID] = true
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if ids[n.ID] {
			n.Attributes["sourceEvidenceState"] = "authenticated"
			n.Attributes["evidenceScope"] = "source-subject/publisher-evidence/item-bytes-mode"
			// The descriptor itself is still declared; add a separate observation.
			n.Provenance = append(n.Provenance, graphdoc.Provenance{Source: o.sourceID, Evidence: evidence, Detected: true})
		}
	}
	if err := g.Canonicalize(); err != nil {
		return graphdoc.Document{}, err
	}
	return g, nil
}
