// Package graphcmd exposes observations from existing authenticated source
// graphs and bounded project syntax. It never produces execution authority.
package graphcmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"os"
	"sync"
)

const QueryAPIVersion = "tplaiter.dev/graph-query/v1"

type Error struct {
	Code  string
	cause error
}

func (e *Error) Error() string { return e.Code }
func (e *Error) Unwrap() error { return e.cause }
func fail(code string) error   { return &Error{Code: code} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "GRAPH_CANCELLED"
	}
	return "GRAPH_SOURCE_ADMISSION"
}
func hashBytes(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
func hashValue(v any) string {
	raw, e := canonicaljson.Canonical(v)
	if e != nil {
		return ""
	}
	return hashBytes(raw)
}

// Query holds untrusted selection bytes, never reader callbacks or grants.
type Query struct {
	APIVersion     string              `json:"apiVersion"`
	Layer          string              `json:"layer"`
	SourceInput    []byte              `json:"sourceInput,omitempty"`
	Selections     []exports.Selection `json:"selections,omitempty"`
	ExpectedDigest string              `json:"expectedDigest,omitempty"`
	Cursor         string              `json:"cursor,omitempty"`
	Limit          int                 `json:"limit"`
	MaxBytes       int                 `json:"maxBytes"`
	Representation string              `json:"representation"`
	Cache          string              `json:"cache"`
}

func (q *Query) Normalize() error {
	if q.APIVersion == "" {
		q.APIVersion = QueryAPIVersion
	}
	if q.APIVersion != QueryAPIVersion {
		return fail("GRAPH_ARGUMENT_INVALID")
	}
	if q.Limit == 0 {
		q.Limit = 64
	}
	if q.MaxBytes == 0 {
		q.MaxBytes = 16384
	}
	if q.Representation == "" {
		q.Representation = "page"
	}
	if q.Cache == "" {
		q.Cache = "read"
	}
	if q.Limit < 1 || q.Limit > 256 || q.MaxBytes < 1024 || q.MaxBytes > 32768 || len(q.SourceInput) > 2<<20 || len(q.Selections) > 16 || len(q.Cursor) > 1024 || (q.Representation != "page" && q.Representation != "whole") || (q.Representation == "whole" && q.Cursor != "") || (q.Cache != "read" && q.Cache != "off" && q.Cache != "refresh") {
		return fail("GRAPH_ARGUMENT_INVALID")
	}
	if q.ExpectedDigest != "" {
		b, e := hex.DecodeString(q.ExpectedDigestAfterPrefix())
		if e != nil || len(b) != 32 || q.ExpectedDigest != "sha256:"+hex.EncodeToString(b) {
			return fail("GRAPH_ARGUMENT_INVALID")
		}
	}
	switch q.Layer {
	case "source":
		if len(q.SourceInput) == 0 || len(q.Selections) != 0 || q.Cache != "read" {
			return fail("GRAPH_ARGUMENT_INVALID")
		}
	case "exports":
		if len(q.SourceInput) == 0 || len(q.Selections) == 0 || q.Cache != "read" {
			return fail("GRAPH_ARGUMENT_INVALID")
		}
	case "ast":
		if len(q.SourceInput) != 0 || len(q.Selections) != 0 {
			return fail("GRAPH_ARGUMENT_INVALID")
		}
	case "stats":
		if q.Cache == "refresh" || (len(q.SourceInput) == 0 && len(q.Selections) != 0) {
			return fail("GRAPH_ARGUMENT_INVALID")
		}
	default:
		return fail("GRAPH_ARGUMENT_INVALID")
	}
	for _, s := range q.Selections {
		if e := s.Validate(); e != nil {
			return fail("GRAPH_SELECTOR_INVALID")
		}
	}
	return nil
}
func (q Query) ExpectedDigestAfterPrefix() string {
	if len(q.ExpectedDigest) >= 7 {
		return q.ExpectedDigest[7:]
	}
	return ""
}
func Operation(layer string) resultdto.Operation {
	switch layer {
	case "source":
		return resultdto.OperationGraphSource
	case "exports":
		return resultdto.OperationGraphExports
	case "ast":
		return resultdto.OperationGraphAST
	default:
		return resultdto.OperationGraphStats
	}
}

type Observation struct {
	mu      sync.Mutex
	runtime *trustload.Runtime
	sources *contextsource.PreparedContextSources
	session *runtimeassembly.ReadSession
	files   *fileSnapshot
	data    resultdto.GraphData
	query   Query
	closed  bool
	refresh *graphdoc.Document
	options runtimeassembly.Options
}

func Prepare(ctx context.Context, r *trustload.Runtime, q Query, opts runtimeassembly.Options) (o *Observation, err error) {
	if ctx == nil || r == nil {
		return nil, fail("GRAPH_SOURCE_ADMISSION")
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := q.Normalize(); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(q)
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(raw, &q); e != nil {
		return nil, e
	}
	o = &Observation{runtime: r, query: q, options: opts}
	ok := false
	defer func() {
		if !ok {
			o.Close()
		}
	}()
	digestQuery := q
	digestQuery.Cursor = ""
	digestQuery.ExpectedDigest = ""
	o.data = resultdto.GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: q.Layer, QueryDigest: hashValue(digestQuery), InputDigests: []string{}, ObservationBasis: "enrolled-source-selection", VerificationLevel: "authenticated-source-pins", CacheState: "disabled", GraphStatus: "ok", Records: []resultdto.GraphRecord{}, Stats: map[string]resultdto.GraphLayerStats{}}
	if len(q.SourceInput) > 0 {
		o.sources, e = contextsource.PrepareContextSources(ctx, r, q.SourceInput)
		if e != nil {
			return nil, fail("GRAPH_SOURCE_ADMISSION")
		}
		g, e := o.sources.SourceGraph(ctx)
		if e != nil {
			return nil, e
		}
		pins, e := o.sources.Pins(ctx)
		if e != nil {
			return nil, e
		}
		o.data.InputDigests = append(o.data.InputDigests, g.Digest)
		o.data.Stats["source"] = resultdto.GraphLayerStats{State: "ready", Digest: g.Digest, Nodes: len(g.Nodes), Edges: len(g.Edges)}
		if q.Layer == "source" {
			o.data.FullGraphDigest = g.Digest
			o.data.Records, e = sourceRecords(g, pins)
			if e != nil {
				return nil, e
			}
		}
		if len(q.Selections) > 0 {
			cs, e := o.sources.Catalogs(ctx)
			if e != nil {
				return nil, e
			}
			catalogs := []exports.Catalog{}
			for _, c := range cs {
				catalogs = append(catalogs, c.Catalog)
			}
			eg, e := exports.ResolveSelections(q.Selections, &g, catalogs)
			if e != nil {
				return nil, fail("GRAPH_SELECTOR_INVALID")
			}
			o.data.InputDigests = append(o.data.InputDigests, eg.Digest)
			o.data.Stats["exports"] = resultdto.GraphLayerStats{State: "ready", Digest: eg.Digest, Nodes: len(eg.Selected), Edges: len(eg.Edges)}
			if q.Layer == "exports" {
				o.data.FullGraphDigest = eg.Digest
				o.data.Records, e = exportRecords(eg)
				if e != nil {
					return nil, e
				}
			}
		}
	}
	if q.Layer == "ast" || q.Layer == "stats" {
		o.data.ObservationBasis = "installed-project-syntax"
		o.data.VerificationLevel = "syntax-go-and-approximate-rust-outline"
		o.session, e = runtimeassembly.OpenReadOnly(ctx, r, opts)
		if e != nil {
			return nil, &Error{Code: "GRAPH_PROJECT_NOT_READY", cause: e}
		}
		if q.Layer == "ast" {
			o.files, e = captureFiles(ctx, r.ProjectContext().RootPath)
			if e != nil {
				return nil, e
			}
			g, state, e := analyze(ctx, o.files, r.ProjectContext().RootPath, q.Cache)
			if e != nil {
				return nil, e
			}
			if q.Cache == "refresh" {
				// Calculation retains pending derived bytes. Only Frame may publish,
				// after admission of its actual complete serialized envelope.
				o.refresh = &g
			}
			o.data.CacheState = state
			o.data.GraphStatus = g.Status
			o.data.InputDigests = append(o.data.InputDigests, o.files.digest)
			o.data.FullGraphDigest = g.Digest
			o.data.Records, e = astRecords(g)
			if e != nil {
				return nil, e
			}
			o.data.Stats["ast"] = resultdto.GraphLayerStats{State: "ready", Digest: g.Digest, Nodes: len(g.Nodes), Edges: len(g.Edges), Diagnostics: len(g.Diagnostics)}
		} else {
			raw, e := cacheRead(r.ProjectContext().RootPath, "current.json")
			switch {
			case errors.Is(e, os.ErrNotExist):
				o.data.CacheState = "missing"
				o.data.Stats["ast"] = resultdto.GraphLayerStats{State: "missing"}
			case e != nil:
				o.data.CacheState = "corrupt"
				o.data.Stats["ast"] = resultdto.GraphLayerStats{State: "corrupt"}
			default:
				v, e := decodeCache(raw)
				if e != nil {
					o.data.CacheState = "corrupt"
					o.data.Stats["ast"] = resultdto.GraphLayerStats{State: "corrupt"}
				} else {
					o.data.CacheState = "unverified"
					o.data.Stats["ast"] = resultdto.GraphLayerStats{State: "stored-input-freshness-unverified", Digest: v.GraphDigest, Nodes: v.NodeCount, Edges: v.EdgeCount, Diagnostics: v.DiagnosticCount}
				}
			}
			for _, layer := range []string{"source", "exports"} {
				if _, ok := o.data.Stats[layer]; !ok {
					o.data.Stats[layer] = resultdto.GraphLayerStats{State: "not-requested"}
				}
			}
			o.data.FullGraphDigest = hashValue(o.data.Stats)
		}
	}
	if q.ExpectedDigest != "" && q.ExpectedDigest != o.data.FullGraphDigest {
		return nil, fail("GRAPH_SOURCE_STALE")
	}
	if e = o.recheckLocked(ctx); e != nil {
		return nil, e
	}
	ok = true
	return o, nil
}
func (o *Observation) recheckLocked(ctx context.Context) error {
	if o == nil || o.closed || o.runtime == nil {
		return fail("GRAPH_SOURCE_STALE")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if o.sources != nil {
		if e := o.sources.RecheckFor(ctx, o.runtime); e != nil {
			return fail("GRAPH_SOURCE_STALE")
		}
	}
	if o.session != nil {
		if e := o.session.Recheck(ctx); e != nil {
			return fail("GRAPH_SOURCE_STALE")
		}
	}
	if o.files != nil {
		return o.files.recheck(ctx)
	}
	return nil
}
func (o *Observation) Recheck(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.recheckLocked(ctx)
}
func (o *Observation) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sources != nil {
		o.sources.Close()
	}
	if o.session != nil {
		o.session.Close()
	}
	if o.files != nil {
		o.files.close()
	}
	o.runtime = nil
	o.closed = true
}
func (o *Observation) Result() (resultdto.GraphData, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return resultdto.GraphData{}, fail("GRAPH_SOURCE_STALE")
	}
	var d resultdto.GraphData
	b, e := json.Marshal(o.data)
	if e == nil {
		e = json.Unmarshal(b, &d)
	}
	return d, e
}

type cursor struct {
	Version string `json:"version"`
	Query   string `json:"query"`
	Graph   string `json:"graph"`
	Next    int    `json:"next"`
}

func pageCursor(d resultdto.GraphData, next int) string {
	b, _ := json.Marshal(cursor{"tplaiter/graph-page/v1", d.QueryDigest, d.FullGraphDigest, next})
	return base64.RawURLEncoding.EncodeToString(b)
}

// Frame measures the actual registered envelope, including project/version,
// escaping and newline. It never accepts a caller-supplied graph or envelope.
func (o *Observation) Frame(ctx context.Context, version string) ([]byte, error) {
	return o.frame(ctx, version, nil)
}

// FrameForMCP admits the actual SDK envelope before any refresh publication.
// The layout controls serialization only; the original runtime owns admission.
func (o *Observation) FrameForMCP(ctx context.Context, version string, l resultwire.GraphFrameLayout) ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, fail("GRAPH_ARGUMENT_INVALID")
	}
	return o.frame(ctx, version, &l)
}
func (o *Observation) frame(ctx context.Context, version string, l *resultwire.GraphFrameLayout) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.recheckLocked(ctx); e != nil {
		return nil, e
	}
	frame, err := makeFrameLayout(o.data, o.query, o.runtime.ProjectContext().ProjectID, o.runtime.ProjectContext().RootPath, version, l)
	if err != nil {
		return nil, err
	}
	if o.refresh != nil {
		if err = o.recheckLocked(ctx); err != nil {
			return nil, err
		}
		// Publication starts at the first cachePublish call. Cancellation or
		// reauthentication failure afterward may retain a derived CAS image.
		if err = publishCache(ctx, o.runtime.ProjectContext().RootPath, o.files, *o.refresh); err != nil {
			return nil, err
		}
		o.refresh = nil
		o.session.Close()
		o.session, err = runtimeassembly.OpenReadOnly(ctx, o.runtime, o.options)
		if err != nil {
			return nil, &Error{Code: "GRAPH_PROJECT_NOT_READY", cause: err}
		}
		if err = o.recheckLocked(ctx); err != nil {
			return nil, err
		}
	}
	return frame, nil
}
func makeFrame(data resultdto.GraphData, q Query, id, root, version string) ([]byte, error) {
	return makeFrameLayout(data, q, id, root, version, nil)
}
func makeFrameLayout(data resultdto.GraphData, q Query, id, root, version string, l *resultwire.GraphFrameLayout) ([]byte, error) {
	if l != nil && (l.Validate() != nil || l.Ceiling != q.MaxBytes) {
		return nil, fail("GRAPH_ARGUMENT_INVALID")
	}
	start := 0
	if q.Cursor != "" {
		b, e := base64.RawURLEncoding.DecodeString(q.Cursor)
		if e != nil {
			return nil, fail("GRAPH_CURSOR_STALE")
		}
		var c cursor
		if e = canonicaljson.DecodeStrict(b, &c); e != nil || c.Version != "tplaiter/graph-page/v1" || c.Query != data.QueryDigest || c.Graph != data.FullGraphDigest || c.Next < 1 || c.Next >= len(data.Records) {
			return nil, fail("GRAPH_CURSOR_STALE")
		}
		start = c.Next
	}
	end := len(data.Records)
	if q.Representation == "page" && end > start+q.Limit {
		end = start + q.Limit
	}
	for {
		d := data
		d.Records = append([]resultdto.GraphRecord{}, data.Records[start:end]...)
		d.Page = resultdto.GraphPage{Representation: q.Representation, Digest: hashValue(d.Records), Returned: end - start, Total: len(data.Records), Omitted: len(data.Records) - (end - start)}
		if end < len(data.Records) {
			d.Page.NextCursor = pageCursor(data, end)
		}
		env := resultdto.New(Operation(q.Layer), version)
		env.Project = &resultdto.Project{ID: id, Root: root}
		if e := env.SetData(d); e != nil {
			return nil, e
		}
		raw, e := resultdto.MarshalCanonical(env)
		if e != nil {
			return nil, e
		}
		raw = append(raw, '\n')
		fits := len(raw) <= q.MaxBytes
		if l != nil {
			wire, err := resultwire.Frame(l.RequestID(), resultwire.Structured(env, false))
			if err != nil {
				return nil, err
			}
			fits = fits && len(wire) <= l.Ceiling
		}
		if fits {
			return raw, nil
		}
		if q.Representation == "whole" || end <= start+1 {
			return nil, fail("GRAPH_OUTPUT_BUDGET")
		}
		end--
	}
}

// ReadSourceInput reads a bounded locator; only Prepare authenticates its contents.
func ReadSourceInput(path string) ([]byte, error) { return readInputFile(path) }
