package contextwindow

import (
	"context"
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
	index    *contextindex.Index
	request  contextindex.Request
	bindings []contextindex.Binding
	raw      []byte
	query    string
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
	return nil
}
