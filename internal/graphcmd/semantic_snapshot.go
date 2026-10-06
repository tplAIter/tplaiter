package graphcmd

import (
	"context"
	"sync"

	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// SemanticFiles owns a read session and confined byte snapshot. It cannot be
// constructed from a path, reader callback, receipt, or caller authority flag.
type SemanticFiles struct {
	mu       sync.Mutex
	self     *SemanticFiles
	runtime  *trustload.Runtime
	session  *runtimeassembly.ReadSession
	snapshot *fileSnapshot
}
type SemanticFileFact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
	Bytes  int    `json:"bytes"`
}

func CaptureSemanticFiles(ctx context.Context, r *trustload.Runtime, opts runtimeassembly.Options) (*SemanticFiles, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, fail("GRAPH_SOURCE_ADMISSION")
	}
	session, e := runtimeassembly.OpenReadOnly(ctx, r, opts)
	if e != nil {
		return nil, e
	}
	snapshot, e := captureFiles(ctx, r.ProjectContext().RootPath)
	if e != nil {
		session.Close()
		return nil, e
	}
	s := &SemanticFiles{runtime: r, session: session, snapshot: snapshot}
	s.self = s
	if e = s.Recheck(ctx); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *SemanticFiles) check(ctx context.Context) error {
	if s == nil || s.self != s || s.runtime == nil || s.runtime.TrustRuntime() == nil || s.session == nil || s.snapshot == nil {
		return fail("GRAPH_SOURCE_STALE")
	}
	if ctx == nil {
		return fail("GRAPH_ARGUMENT_INVALID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.session.Recheck(ctx); e != nil {
		return e
	}
	return s.snapshot.recheck(ctx)
}
func (s *SemanticFiles) Recheck(ctx context.Context) error {
	if s == nil {
		return fail("GRAPH_SOURCE_STALE")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(ctx)
}
func (s *SemanticFiles) Images(ctx context.Context) ([]semanticgraph.SourceFile, []SemanticFileFact, string, error) {
	if s == nil {
		return nil, nil, "", fail("GRAPH_SOURCE_STALE")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx); e != nil {
		return nil, nil, "", e
	}
	images := make([]semanticgraph.SourceFile, len(s.snapshot.files))
	for i, f := range s.snapshot.files {
		images[i] = semanticgraph.SourceFile{Path: f.Path, Bytes: append([]byte(nil), f.Bytes...)}
	}
	facts := make([]SemanticFileFact, len(s.snapshot.facts))
	for i, f := range s.snapshot.facts {
		facts[i] = SemanticFileFact{f.Path, f.Hash, f.Mode, f.Bytes}
	}
	return images, facts, s.snapshot.digest, nil
}
func (s *SemanticFiles) Close() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot != nil {
		s.snapshot.close()
		s.snapshot = nil
	}
	if s.session != nil {
		s.session.Close()
		s.session = nil
	}
	s.runtime = nil
}
