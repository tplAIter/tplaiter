package contextindex

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func (i *Index) excerpts(ctx context.Context, p *Packet, req Request, bindings []Binding) error {
	limit := req.MaxExcerptBytes
	if limit == 0 {
		limit = 512
	}
	if limit < 1 || limit > 2048 || len(bindings) > 128 {
		return diagnostic(Invalid, "excerpt limits")
	}
	byID := map[string]Binding{}
	for _, b := range bindings {
		if _, ok := byID[b.SourceID]; ok {
			return diagnostic(Ambiguous, b.SourceID)
		}
		byID[b.SourceID] = b
	}
	needed := map[string]bool{}
	for _, r := range p.Records {
		needed[r.SourceID] = true
	}
	snapshots := map[string]*trustverify.SourceSnapshot{}
	for _, s := range p.Sources {
		if !needed[s.ID] {
			continue
		}
		b, ok := byID[s.ID]
		if !ok {
			return diagnostic(Missing, s.ID)
		}
		if err := i.observe(ctx, b); err != nil {
			return err
		}
		snapshot, err := b.Runtime.VerifiedSnapshot(b.Resolution)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", s.ID, err)
		}
		snapshots[s.ID] = snapshot
		p.SourceEvidence = append(p.SourceEvidence, SourceEvidence{SourceID: s.ID, StatementCAS: s.Anchor.StatementCAS, Scope: "source-subject/publisher-evidence/item-bytes-mode"})
	}
	for _, r := range p.Records {
		snapshot := snapshots[r.SourceID]
		if snapshot == nil {
			return diagnostic(Missing, r.SourceID)
		}
		blob, ok := snapshot.Blob(r.Path)
		if !ok {
			return diagnostic(Missing, r.ID)
		}
		if len(blob) > 1<<20 {
			return diagnostic(Budget, r.ID)
		}
		if !utf8.Valid(blob) {
			return diagnostic(Invalid, r.ID)
		}
		excerpt, err := boundedExcerpt(r, blob, limit)
		if err != nil {
			return err
		}
		excerpt.Digest = i.items[r.ItemID].ContentSHA256
		p.Excerpts = append(p.Excerpts, excerpt)
	}
	// Authenticate again before releasing retained immutable bytes. This bounds
	// freshness at return; it does not claim an atomic observation of all sources.
	for _, s := range p.Sources {
		if needed[s.ID] {
			if err := i.observe(ctx, byID[s.ID]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Index) observe(ctx context.Context, b Binding) error {
	observation, err := knowledge.ObserveSource(ctx, b.Runtime, b.Resolution, i.raw, b.SourceID)
	if err != nil {
		return fmt.Errorf("observe %s: %w", b.SourceID, err)
	}
	if _, err = observation.Graph(); err != nil {
		return fmt.Errorf("observation %s: %w", b.SourceID, err)
	}
	return nil
}

func boundedExcerpt(r Record, blob []byte, limit int) (contextpack.SourceExcerpt, error) {
	lines := strings.Split(string(blob), "\n")
	if r.Line < 1 || r.Line > len(lines) {
		return contextpack.SourceExcerpt{}, diagnostic(Stale, r.ID)
	}
	end := r.Line - 1
	content := ""
	for n := r.Line - 1; n < len(lines) && n < r.Line-1+8; n++ {
		next := lines[n]
		if n > r.Line-1 {
			next = content + "\n" + next
		}
		if len(next) > limit {
			break
		}
		content = next
		end = n + 1
	}
	if end < r.Line {
		return contextpack.SourceExcerpt{}, diagnostic(Budget, r.ID)
	}
	return contextpack.SourceExcerpt{NodeID: r.ID, Path: r.Path, Start: r.Line, End: end, Content: content}, nil
}
