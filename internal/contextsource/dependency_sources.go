package contextsource

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/tplAIter/tplaiter/internal/contextauth"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type contextSourceRecord struct {
	resolution, original *trustverify.VerifiedResolution
}

// PreparedContextSources owns transport verification and the shared source closure.
// Its projections supply data, never a permit or caller-selected reader.
type PreparedContextSources struct {
	mu        sync.Mutex
	installed *trustload.Runtime
	closure   *contextauth.VerifiedSourceClosure
	records   map[string]contextSourceRecord
}

func PrepareContextSources(ctx context.Context, r *trustload.Runtime, raw []byte) (*PreparedContextSources, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, errContextSources
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	in, e := DecodeSourceSelectionV2(append([]byte(nil), raw...))
	if e != nil {
		return nil, e
	}
	inputs := append([]ContextSourceProof{in.Root}, in.Sources...)
	resolutions := []*trustverify.VerifiedResolution{}
	for _, proof := range inputs {
		v, e := r.TrustRuntime().VerifySubject(ctx, contextSubject(proof), contextEvidence(proof))
		if e != nil {
			return nil, e
		}
		resolutions = append(resolutions, v)
	}
	c, e := contextauth.AdmitSourceClosure(ctx, r, resolutions[0], resolutions[1:])
	if e != nil {
		return nil, e
	}
	p := &PreparedContextSources{installed: r, closure: c, records: map[string]contextSourceRecord{}}
	pins, e := c.Pins(ctx)
	if e != nil {
		c.Close()
		return nil, e
	}
	for _, pin := range pins {
		v, e := c.Resolution(ctx, pin.Alias)
		if e != nil {
			c.Close()
			return nil, e
		}
		p.records[pin.Alias] = contextSourceRecord{v, v}
	}
	return p, nil
}
func (p *PreparedContextSources) checkLocked(ctx context.Context) error {
	if p.installed == nil || p.closure == nil || len(p.records) == 0 {
		return errContextSources
	}
	for _, v := range p.records {
		if v.resolution == nil || v.resolution != v.original {
			return errContextSources
		}
	}
	return p.closure.RecheckFor(ctx, p.installed)
}
func (p *PreparedContextSources) Recheck(ctx context.Context) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkLocked(ctx)
}
func (p *PreparedContextSources) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return errContextSources
	}
	return p.checkLocked(ctx)
}
func (p *PreparedContextSources) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closure != nil {
		p.closure.Close()
	}
	p.closure = nil
	p.records = nil
	p.installed = nil
}
func contextCopy[T any](in T) (T, error) {
	var out T
	raw, e := json.Marshal(in)
	if e != nil {
		return out, e
	}
	e = json.Unmarshal(raw, &out)
	return out, e
}
func (p *PreparedContextSources) borrowClosure(ctx context.Context, r *trustload.Runtime) (*contextauth.VerifiedSourceClosure, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r == nil || r != p.installed {
		return nil, errContextSources
	}
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return p.closure.Borrow(ctx, r)
}
func (p *PreparedContextSources) Pins(ctx context.Context) ([]deps.PinnedSource, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return p.closure.Pins(ctx)
}
func (p *PreparedContextSources) SourceGraph(ctx context.Context) (deps.SourceGraph, error) {
	if p == nil {
		return deps.SourceGraph{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return deps.SourceGraph{}, e
	}
	return p.closure.SourceGraph(ctx)
}
func (p *PreparedContextSources) Catalogs(ctx context.Context) ([]exports.SourceCatalog, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return p.closure.Catalogs(ctx)
}
func (p *PreparedContextSources) CatalogData(ctx context.Context, alias string) (exports.CatalogData, error) {
	if p == nil {
		return exports.CatalogData{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return exports.CatalogData{}, e
	}
	return p.closure.CatalogData(ctx, alias)
}
func (p *PreparedContextSources) Resolution(ctx context.Context, alias string) (*trustverify.VerifiedResolution, error) {
	if p == nil {
		return nil, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return nil, e
	}
	return p.closure.Resolution(ctx, alias)
}
func (p *PreparedContextSources) RootPin(ctx context.Context) (deps.PinnedSource, error) {
	if p == nil {
		return deps.PinnedSource{}, errContextSources
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.checkLocked(ctx); e != nil {
		return deps.PinnedSource{}, e
	}
	return p.closure.RootPin(ctx)
}
