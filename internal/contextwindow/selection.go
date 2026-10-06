package contextwindow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/contextindex"
)

// Selection is reconstructed through C03. No raw packet/boolean can construct
// one. Declared metadata stays declared; opted source bytes require C03 bindings.
type Selection struct{ *selectionRecord }

func selectionFresh(ctx context.Context, s *Selection) error {
	if s == nil || s.selectionRecord == nil {
		return fail(Invalid, "selection")
	}
	return s.fresh(ctx)
}

type selectionRecord struct {
	index      *contextindex.Index
	request    contextindex.Request
	bindings   []contextindex.Binding
	wire       []byte
	projection string
	raw        []byte
	query      string
}

func Select(ctx context.Context, index *contextindex.Index, request contextindex.Request, bindings []contextindex.Binding) (*Selection, error) {
	if e := checkContext(ctx); e != nil {
		return nil, e
	}
	if index == nil {
		return nil, fail(Invalid, "index")
	}
	request.Required = append([]string(nil), request.Required...)
	bindings = append([]contextindex.Binding(nil), bindings...)
	p, e := index.Retrieve(ctx, request, bindings)
	if e != nil {
		return nil, fmt.Errorf("select context: %w", e)
	}
	raw, e := encode(p)
	if e != nil {
		return nil, e
	}
	query, e := encode(request)
	if e != nil {
		return nil, e
	}
	return &Selection{selectionRecord: &selectionRecord{index: index, request: request, bindings: bindings, raw: raw, query: digest(query)}}, nil
}

func (s *selectionRecord) fresh(ctx context.Context) error {
	if s == nil || s.index == nil || len(s.raw) == 0 {
		return fail(Invalid, "selection")
	}
	p, e := s.index.Retrieve(ctx, s.request, s.bindings)
	if e != nil {
		return fmt.Errorf("refresh selection: %w", e)
	}
	raw, e := encode(p)
	if e != nil {
		return e
	}
	if digest(raw) != digest(s.raw) {
		return fail(Stale, "selection pins/floor")
	}
	if s.projection != "" {
		var facts any
		switch s.projection {
		case contextindex.RootFactsAPIVersion:
			facts, e = contextindex.EncodeRootFactsV2(p)
		case contextindex.SourceFactsAPIVersion:
			facts, e = contextindex.EncodeSourceFactsV3(p)
		default:
			return fail(Invalid, "selection projection")
		}
		if e != nil {
			return e
		}
		wire, e := encode(facts)
		if e != nil || digest(wire) != digest(s.wire) {
			return fail(Stale, "selection projection bytes")
		}
	}
	return nil
}

// FactorRootSelectionV2 derives only from this owned, authenticated selection.
// The original logical bytes and concrete source bindings remain the freshness floor.
func FactorRootSelectionV2(ctx context.Context, s *Selection) (*Selection, error) {
	if e := selectionFresh(ctx, s); e != nil {
		return nil, e
	}
	if !s.request.IncludeExcerpts || len(s.bindings) != 1 || s.bindings[0].Runtime == nil || s.bindings[0].Resolution == nil {
		return nil, fail(Invalid, "authenticated ROOT projection")
	}
	var p contextindex.Packet
	if e := json.Unmarshal(s.raw, &p); e != nil {
		return nil, e
	}
	facts, e := contextindex.EncodeRootFactsV2(p)
	if e != nil {
		return nil, e
	}
	wire, e := encode(facts)
	if e != nil {
		return nil, e
	}
	copy := *s.selectionRecord
	copy.wire, copy.projection = wire, contextindex.RootFactsAPIVersion
	return &Selection{selectionRecord: &copy}, nil
}
func (s *selectionRecord) deliveryBytes() []byte {
	if s.projection != "" {
		return s.wire
	}
	return s.raw
}

// FactorProjectSelectionV3 retains the opaque C03 selection and every concrete
// same-runtime source binding. Data facts cannot replace source authentication.
func FactorProjectSelectionV3(ctx context.Context, s *Selection) (*Selection, error) {
	if e := selectionFresh(ctx, s); e != nil {
		return nil, e
	}
	if !s.request.IncludeExcerpts || len(s.bindings) < 2 || len(s.bindings) > 32 {
		return nil, fail(Invalid, "authenticated source projection")
	}
	var p contextindex.Packet
	if e := json.Unmarshal(s.raw, &p); e != nil {
		return nil, e
	}
	if len(s.bindings) != len(p.Sources) {
		return nil, fail(Invalid, "complete source bindings")
	}
	byID := map[string]contextindex.Binding{}
	runtime := s.bindings[0].Runtime
	for _, b := range s.bindings {
		if b.Runtime == nil || b.Runtime != runtime || b.Resolution == nil || byID[b.SourceID].SourceID != "" {
			return nil, fail(Invalid, "unique same-runtime source bindings")
		}
		byID[b.SourceID] = b
	}
	for _, source := range p.Sources {
		if byID[source.ID].SourceID == "" {
			return nil, fail(Invalid, "missing concrete source binding")
		}
	}
	facts, e := contextindex.EncodeSourceFactsV3(p)
	if e != nil {
		return nil, e
	}
	wire, e := encode(facts)
	if e != nil {
		return nil, e
	}
	copy := *s.selectionRecord
	copy.wire, copy.projection = wire, contextindex.SourceFactsAPIVersion
	return &Selection{selectionRecord: &copy}, nil
}
