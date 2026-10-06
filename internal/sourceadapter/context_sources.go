package sourceadapter

import (
	"context"
	"io/fs"
	"sync"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// ContextSource owns admission, not a checkout reader or detached render grant.
// Its lifetime belongs to the caller; closing it invalidates dependent intents.
type ContextSource struct {
	mu                   sync.Mutex
	runtime              *trustload.Runtime
	sources              *contextsource.PreparedContextSources
	input                []byte
	alias, name, version string
}

func ResolveContextSources(ctx context.Context, runtime *trustload.Runtime, home, ref string, raw []byte) (*ContextSource, error) {
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrMismatch
	}
	input := append([]byte(nil), raw...)
	selection, err := contextsource.DecodeSourceSelectionV2(input)
	if err != nil {
		return nil, err
	}
	alias, name, version, err := resolveRootLocator(ctx, home, ref, selection.Root.Subject)
	if err != nil {
		return nil, err
	}
	sources, err := contextsource.PrepareContextSources(ctx, runtime, input)
	if err != nil {
		return nil, err
	}
	out := &ContextSource{runtime: runtime, sources: sources, input: input, alias: alias, version: version}
	complete := false
	defer func() {
		if !complete {
			out.Close()
		}
	}()
	projected, err := out.Root(ctx, runtime)
	if err != nil {
		return nil, err
	}
	if name != "" && name != projected.Name {
		return nil, ErrMismatch
	}
	out.name = projected.Name
	complete = true
	return out, nil
}

func (s *ContextSource) check(ctx context.Context, r *trustload.Runtime) error {
	if s == nil || ctx == nil || r == nil || s.runtime != r || s.sources == nil {
		return ErrMismatch
	}
	return s.sources.RecheckFor(ctx, r)
}

// Root returns calculation data only. New preparation reconstructs its own
// retained root snapshot from Sources instead of accepting this FS as authority.
func (s *ContextSource) Root(ctx context.Context, r *trustload.Runtime) (*Source, error) {
	if s == nil {
		return nil, ErrMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, r); err != nil {
		return nil, err
	}
	pin, err := s.sources.RootPin(ctx)
	if err != nil {
		return nil, err
	}
	resolution, err := s.sources.Resolution(ctx, pin.Alias)
	if err != nil {
		return nil, err
	}
	snapshot, err := operationtrust.SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	contract, err := fs.ReadFile(snapshot, "template.contract.json")
	if err != nil {
		return nil, err
	}
	manifest, err := fs.ReadFile(snapshot, "template.manifest.yaml")
	if err != nil {
		return nil, err
	}
	if _, err = contextsource.DecodeNativeContextContractV2(contract, manifest); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(snapshot)
	if err != nil {
		return nil, err
	}
	if err = s.check(ctx, r); err != nil {
		return nil, err
	}
	return &Source{Input: append([]byte(nil), s.input...), Snapshot: snapshot, Alias: s.alias, Name: tpl.Metadata.Name, Version: s.version}, nil
}

func (s *ContextSource) Sources(ctx context.Context, r *trustload.Runtime) (*contextsource.PreparedContextSources, error) {
	if s == nil {
		return nil, ErrMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, r); err != nil {
		return nil, err
	}
	return s.sources, nil
}
func (s *ContextSource) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if s == nil {
		return ErrMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(ctx, r)
}
func (s *ContextSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sources != nil {
		s.sources.Close()
	}
	s.sources = nil
	s.runtime = nil
	s.input = nil
}
