package contextsource

import (
	"context"
	"fmt"
	"sync"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// NativeModifierSource pairs opaque evidence with an opaque source read. Public
// labels and JSON cannot create either object. Constructor rechecks both.
type NativeModifierSource struct {
	Resolution *trustverify.VerifiedResolution
	Source     *deps.VerifiedSource
}

// PreparedNativeModifier is same-runtime inert calculation custody only. It
// exposes no material getter, effect permit, arbitrary reader or file-map writer.
type PreparedNativeModifier struct {
	mu         sync.Mutex
	owner      *trustload.Runtime
	raw        []byte
	rootAlias  string
	sources    []NativeModifierSource
	projection *exports.ProjectedModifier
	closed     bool
}

// PrepareNativeModifier binds operator-authored constraints as calculation
// input, not an upstream descriptor certificate. Source-bound descriptor and
// action/publication integration require the separately reserved owner seam.
func PrepareNativeModifier(ctx context.Context, r *trustload.Runtime, rootAlias string, authored []byte, sources []NativeModifierSource) (*PreparedNativeModifier, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || len(sources) == 0 {
		return nil, fmt.Errorf("NATIVE_MODIFIER_SOURCE")
	}
	p := &PreparedNativeModifier{owner: r, raw: append([]byte(nil), authored...), rootAlias: rootAlias, sources: append([]NativeModifierSource(nil), sources...)}
	if e := p.rederive(ctx, r); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *PreparedNativeModifier) rederive(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || p.closed || ctx == nil || ctx.Err() != nil || r == nil || r != p.owner || r.TrustRuntime() == nil {
		return fmt.Errorf("NATIVE_MODIFIER_RUNTIME")
	}
	stable := r.TrustRuntime()
	reader, e := deps.NewSourceReader(stable)
	if e != nil {
		return e
	}
	verified := []*deps.VerifiedSource{}
	for _, s := range p.sources {
		if s.Resolution == nil || s.Source == nil || !s.Resolution.ValidFor(stable, stable.Binding()) {
			return fmt.Errorf("NATIVE_MODIFIER_RUNTIME")
		}
		pin, ok := s.Source.AcceptedPin()
		if !ok {
			return fmt.Errorf("NATIVE_MODIFIER_SOURCE")
		}
		// Fresh authorization/evidence and original subject are checked under the
		// same runtime before the SourceReader can produce the replacement read.
		fresh, e := stable.VerifySubject(ctx, s.Resolution.Subject(), s.Resolution.Evidence())
		if e != nil {
			return e
		}
		v, e := reader.Read(ctx, fresh, pin)
		if e != nil {
			return e
		}
		verified = append(verified, v)
	}
	projected, e := exports.ProjectAuthoredModifier(ctx, p.raw, p.rootAlias, verified)
	if e != nil {
		return e
	}
	p.projection = projected
	return nil
}
func (p *PreparedNativeModifier) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil {
		return fmt.Errorf("NATIVE_MODIFIER_ZERO")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rederive(ctx, r)
}
func (p *PreparedNativeModifier) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for i := range p.raw {
		p.raw[i] = 0
	}
	p.raw = nil
	p.sources = nil
	p.projection = nil
	p.owner = nil
}
