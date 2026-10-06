package semanticpreview

import (
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const ResultVersion = "tplaiter.dev/semantic-preview-result/v1"

// Preview retains authenticated observation and original file images. Its
// calculated edits never represent permission to mutate or execute a project.
type Preview struct {
	mu      sync.Mutex
	self    *Preview
	files   *graphcmd.SemanticFiles
	runtime *trustload.Runtime
	data    resultdto.SemanticPreviewData
}

func Prepare(ctx context.Context, r *trustload.Runtime, q Request, opts runtimeassembly.Options) (*Preview, error) {
	if e := q.Validate(); e != nil {
		return nil, e
	}
	raw, e := canonicaljson.Canonical(q)
	if e != nil {
		return nil, e
	}
	q, e = DecodeRequest(raw)
	if e != nil {
		return nil, e
	}
	files, e := graphcmd.CaptureSemanticFiles(ctx, r, opts)
	if e != nil {
		return nil, e
	}
	images, facts, manifest, e := files.Images(ctx)
	if e != nil {
		files.Close()
		return nil, e
	}
	data, e := calculate(ctx, q, images, facts, manifest)
	if e != nil {
		files.Close()
		return nil, e
	}
	p := &Preview{files: files, runtime: r, data: data}
	p.self = p
	if e = p.Recheck(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
func calculate(ctx context.Context, q Request, images []semanticgraph.SourceFile, facts []graphcmd.SemanticFileFact, manifest string) (resultdto.SemanticPreviewData, error) {
	d := resultdto.SemanticPreviewData{APIVersion: ResultVersion, Action: q.Action, Basis: "installed-project-observed-bytes", VerificationLevel: "go-syntax-only", CompilerVerification: "not-performed", Scope: "selected-go-files", NoEffects: true, SourceManifestDigest: manifest, Images: []resultdto.SemanticImage{}, AddedNodes: []string{}, RemovedNodes: []string{}, AddedEdges: []graphdoc.Edge{}, RemovedEdges: []graphdoc.Edge{}, Edits: []resultdto.SemanticEditMapping{}}
	raw, e := canonicaljson.Canonical(q)
	if e != nil {
		return d, e
	}
	d.RequestDigest = evidencecas.Digest(raw)
	wanted := map[string]bool{}
	for _, path := range q.Paths {
		wanted[path] = true
	}
	for _, edit := range q.Edits {
		wanted[edit.Path] = true
	}
	modes := map[string]uint32{}
	for _, f := range facts {
		modes[f.Path] = f.Mode
	}
	before := []semanticgraph.SourceFile{}
	parsed := map[string]*parsedGo{}
	for _, f := range images {
		if !wanted[f.Path] {
			continue
		}
		if e = ctx.Err(); e != nil {
			return d, e
		}
		g, err := parseGo(f.Path, f.Bytes)
		if err != nil {
			return d, err
		}
		parsed[f.Path] = g
		before = append(before, semanticgraph.SourceFile{Path: f.Path, Bytes: append([]byte(nil), f.Bytes...)})
	}
	if len(parsed) != len(wanted) {
		return d, ErrAnchor
	}
	sort.Slice(before, func(i, j int) bool { return before[i].Path < before[j].Path })
	d.BeforeGraph, e = semanticgraph.AnalyzeFiles(ctx, before, semanticgraph.Options{})
	if e != nil {
		return d, e
	}
	byPath := map[string][]splice{}
	for _, edit := range q.Edits {
		if edit.BeforeGraphDigest != d.BeforeGraph.Digest {
			return d, ErrAnchor
		}
		s, err := parsed[edit.Path].resolve(edit)
		if err != nil {
			return d, err
		}
		byPath[edit.Path] = append(byPath[edit.Path], s)
	}
	after := []semanticgraph.SourceFile{}
	for _, f := range before {
		g := parsed[f.Path]
		b := append([]byte(nil), f.Bytes...)
		m := []resultdto.SemanticEditMapping{}
		if len(byPath[f.Path]) > 0 {
			b, m, e = applySplices(g, byPath[f.Path])
			if e != nil {
				return d, e
			}
		}
		if len(b) > semanticgraph.MaxFileBytes {
			return d, ErrBudget
		}
		next, err := parseGo(f.Path, b)
		if err != nil {
			return d, err
		}
		diff, err := unifiedDiff(f.Path, f.Bytes, b)
		if err != nil {
			return d, err
		}
		d.Images = append(d.Images, resultdto.SemanticImage{Path: f.Path, Mode: modes[f.Path], Before: append([]byte(nil), f.Bytes...), After: b, BeforeDigest: evidencecas.Digest(f.Bytes), AfterDigest: evidencecas.Digest(b), BeforeBytes: len(f.Bytes), AfterBytes: len(b), BeforeAnchors: append([]resultdto.SemanticAnchor{}, g.anchors...), AfterAnchors: append([]resultdto.SemanticAnchor{}, next.anchors...), Diff: diff})
		d.Edits = append(d.Edits, m...)
		after = append(after, semanticgraph.SourceFile{Path: f.Path, Bytes: b})
	}
	d.AfterGraph, e = semanticgraph.AnalyzeFiles(ctx, after, semanticgraph.Options{})
	if e != nil {
		return d, e
	}
	d.AddedNodes, d.RemovedNodes = nodeDelta(d.BeforeGraph, d.AfterGraph)
	d.AddedEdges, d.RemovedEdges = edgeDelta(d.BeforeGraph, d.AfterGraph)
	raw, e = canonicaljson.Canonical(d)
	if e != nil {
		return d, e
	}
	d.PreviewDigest = evidencecas.Digest(raw)
	if e := resultdto.ValidateSemanticPreviewData(d); e != nil {
		return d, e
	}
	return d, nil
}
func nodeDelta(a, b graphdoc.Document) ([]string, []string) {
	old := map[string]bool{}
	next := map[string]bool{}
	for _, n := range a.Nodes {
		old[n.ID] = true
	}
	for _, n := range b.Nodes {
		next[n.ID] = true
	}
	added, removed := []string{}, []string{}
	for id := range next {
		if !old[id] {
			added = append(added, id)
		}
	}
	for id := range old {
		if !next[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
func edgeDelta(a, b graphdoc.Document) ([]graphdoc.Edge, []graphdoc.Edge) {
	key := func(e graphdoc.Edge) string { b, _ := canonicaljson.Canonical(e); return string(b) }
	old, next := map[string]bool{}, map[string]bool{}
	for _, e := range a.Edges {
		old[key(e)] = true
	}
	for _, e := range b.Edges {
		next[key(e)] = true
	}
	added, removed := []graphdoc.Edge{}, []graphdoc.Edge{}
	for _, e := range b.Edges {
		if !old[key(e)] {
			added = append(added, e)
		}
	}
	for _, e := range a.Edges {
		if !next[key(e)] {
			removed = append(removed, e)
		}
	}
	return added, removed
}
func (p *Preview) check(ctx context.Context) error {
	if p == nil || p.self != p || p.files == nil || p.runtime == nil {
		return ErrAnchor
	}
	return p.files.Recheck(ctx)
}
func (p *Preview) Recheck(ctx context.Context) error {
	if p == nil {
		return ErrAnchor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.check(ctx)
}
func (p *Preview) Close() {
	if p == nil || p.self != p {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.files != nil {
		p.files.Close()
		p.files = nil
	}
	p.runtime = nil
}
func (p *Preview) Result(ctx context.Context) (resultdto.SemanticPreviewData, error) {
	if p == nil {
		return resultdto.SemanticPreviewData{}, ErrAnchor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.check(ctx); e != nil {
		return resultdto.SemanticPreviewData{}, e
	}
	raw, e := json.Marshal(p.data)
	var d resultdto.SemanticPreviewData
	if e == nil {
		e = json.Unmarshal(raw, &d)
	}
	return d, e
}
func (p *Preview) Frame(ctx context.Context, version string, maxBytes int) ([]byte, error) {
	return p.frame(ctx, version, maxBytes, nil)
}
func (p *Preview) FrameForMCP(ctx context.Context, version string, l resultwire.GraphFrameLayout) ([]byte, error) {
	if e := l.Validate(); e != nil {
		return nil, e
	}
	return p.frame(ctx, version, l.Ceiling, &l)
}
func (p *Preview) frame(ctx context.Context, version string, maxBytes int, l *resultwire.GraphFrameLayout) ([]byte, error) {
	if p == nil {
		return nil, ErrAnchor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.check(ctx); e != nil {
		return nil, e
	}
	if maxBytes < 1024 || maxBytes > 32768 {
		return nil, ErrRequest
	}
	project := p.runtime.ProjectContext()
	return encodeFrame(p.data, project.ProjectID, project.RootPath, version, maxBytes, l)
}
func encodeFrame(d resultdto.SemanticPreviewData, id, root, version string, maxBytes int, l *resultwire.GraphFrameLayout) ([]byte, error) {
	env := resultdto.New(resultdto.OperationSemanticPreview, version)
	env.Project = &resultdto.Project{ID: id, Root: root}
	if e := env.SetData(d); e != nil {
		return nil, e
	}
	raw, e := resultdto.MarshalCanonical(env)
	if e != nil {
		return nil, e
	}
	raw = append(raw, '\n')
	if len(raw) > maxBytes {
		return nil, ErrBudget
	}
	if l != nil {
		if l.Validate() != nil || l.Ceiling != maxBytes {
			return nil, ErrRequest
		}
		wire, e := resultwire.Frame(l.RequestID(), resultwire.Structured(env, false))
		if e != nil {
			return nil, e
		}
		if len(wire) > maxBytes {
			return nil, ErrBudget
		}
	}
	return raw, nil
}
