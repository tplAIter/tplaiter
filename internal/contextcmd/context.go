package contextcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const (
	Invalid           = "CONTEXT_FRONTEND_INVALID"
	Missing           = "CONTEXT_FRONTEND_MISSING"
	Stale             = "CONTEXT_FRONTEND_STALE"
	Budget            = "CONTEXT_FRONTEND_BUDGET"
	SourceUnavailable = "CONTEXT_PROVIDER_UNAVAILABLE"
	WindowUnknown     = contextwindow.Unknown
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }
func fail(code string) error   { return &Error{Code: code} }

// Request contains selectors and finite byte bounds, never host window claims,
// caller readers, arbitrary catalog JSON, filesystem roots or execution hooks.
type Request struct {
	Action          string   `json:"action"`
	ID              string   `json:"id,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Path            string   `json:"path,omitempty"`
	Text            string   `json:"text,omitempty"`
	CatalogPath     string   `json:"catalogPath,omitempty"`
	Required        []string `json:"required,omitempty"`
	Limit           int      `json:"limit,omitempty"`
	MaxRecords      int      `json:"maxRecords,omitempty"`
	MaxBytes        int      `json:"maxBytes,omitempty"`
	MaxExcerptBytes int      `json:"maxExcerptBytes,omitempty"`
	Cursor          string   `json:"cursor,omitempty"`
	Snapshot        string   `json:"snapshot,omitempty"`
}

type cursor struct {
	Version string  `json:"version"`
	Binding string  `json:"binding"`
	Offset  int     `json:"offset"`
	Request Request `json:"request"`
}

// Run uses one actual installed runtime and a held read-only project session.
// Each call reconstructs its index from freshly verified immutable source;
// cursors survive process boundaries without a home cache or task ledger.
func Run(ctx context.Context, r *trustload.Runtime, req Request) (resultdto.ContextData, error) {
	empty := resultdto.ContextData{}
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return empty, fail(Invalid)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var continuation *cursor
	action := req.Action
	if action == "continue" {
		// A continuation's selectors/bounds are carried in its self-contained
		// request. Caller replacements are refused, not silently ignored.
		supplied := req
		supplied.Action = ""
		supplied.Cursor = ""
		supplied.Snapshot = ""
		if !reflectEmpty(supplied) {
			return empty, fail(Invalid)
		}
		c, err := decodeCursor(req.Cursor)
		if err != nil {
			return empty, err
		}
		continuation = &c
		snapshot := req.Snapshot
		req = c.Request
		req.Snapshot = snapshot
	}
	if err := normalize(&req); err != nil {
		return empty, err
	}
	session, err := runtimeassembly.OpenReadOnly(ctx, r, runtimeassembly.Options{})
	if err != nil {
		return empty, err
	}
	defer session.Close()
	a, err := admit(ctx, r, req.CatalogPath)
	if err != nil {
		return empty, err
	}
	idx, err := contextindex.New(a.raw, nil)
	if err != nil {
		return empty, err
	}
	binding := contextindex.Binding{SourceID: a.catalog.Sources[0].ID, Runtime: r.TrustRuntime(), Resolution: a.resolution}
	project := r.ProjectContext()
	scopeBytes, _ := json.Marshal(struct {
		Project       trustload.ProjectContext
		Catalog, Lock string
	}{project, evidencecas.Digest(a.raw), evidencecas.Digest(a.rootBytes)})
	snapshot := evidencecas.Digest(scopeBytes)
	if req.Snapshot != "" && req.Snapshot != snapshot {
		return empty, fail(Stale)
	}
	bindingID := requestBinding(req, snapshot)
	offset := 0
	if continuation != nil {
		if continuation.Binding != bindingID {
			return empty, fail(Stale)
		}
		offset = continuation.Offset
	}
	out := resultdto.ContextData{Action: action, Snapshot: snapshot, CatalogOrigin: a.origin, Entries: []resultdto.ContextEntry{}, WindowState: "unknown", WindowReason: WindowUnknown}
	coreReq := contextindex.Request{Limit: 1, MaxRecords: req.MaxRecords, MaxBytes: req.MaxBytes, MaxExcerptBytes: req.MaxExcerptBytes, Required: append([]string(nil), req.Required...)}
	if req.Action == "get" {
		coreReq.Query = contextindex.Query{ID: req.ID, Kind: req.Kind, Path: req.Path, Text: req.Text, One: true}
		coreReq.IncludeExcerpts = true
	} else {
		matches := entries(a.catalog)
		selected := matches[:0]
		for _, e := range matches {
			if req.ID != "" && req.ID != e.ID || req.Kind != "" && req.Kind != e.Kind || req.Path != "" && req.Path != e.Path {
				continue
			}
			name := e.ID
			if e.Kind == "path" {
				name = e.Path
			}
			if req.Text != "" && !strings.Contains(e.ID+"\n"+e.Path+"\n"+name, req.Text) {
				continue
			}
			selected = append(selected, e)
		}
		out.Total = len(selected)
		if offset < 0 || offset > len(selected) || (continuation != nil && offset == len(selected)) {
			return empty, fail(Stale)
		}
		end := offset + req.Limit
		if end > len(selected) {
			end = len(selected)
		}
		// C03 closes the union of page items and explicit required task context.
		// Pagination only excludes optional primary matches, never their floor.
		for _, e := range selected[offset:end] {
			e.ResourceURI = ResourceURI(project.Key, snapshot, e.ID)
			out.Entries = append(out.Entries, e)
			coreReq.Required = append(coreReq.Required, e.ID)
		}
		coreReq.Query = contextindex.Query{ID: "installed:resource:no-primary"}
		if end < len(selected) && req.Action != "plan" {
			c := cursor{Version: "tplaiter.dev/context-cursor/v1", Binding: bindingID, Offset: end, Request: req}
			c.Request.Snapshot = ""
			b, _ := json.Marshal(c)
			out.NextCursor = base64.RawURLEncoding.EncodeToString(b)
		}
	}
	packet, err := idx.Retrieve(ctx, coreReq, []contextindex.Binding{binding})
	if err != nil {
		return empty, err
	}
	// The C04 adapter admits and measures the complete local transport wire,
	// reserves its actual response byte obligations and records a delivery receipt.
	// Its fixed byte ceiling establishes no trusted model window.
	delivered, plan, profile, spending, err := deliverLocalContext(ctx, idx, coreReq, binding, req, snapshot, packet)
	if err != nil {
		return empty, err
	}
	packet = delivered
	out.Packet = &packet
	out.BytePlan, out.ByteProfile, out.Spending = &plan, &profile, &spending
	out.RetrievalState = "local-byte-delivery-finished"
	if req.Action == "plan" {
		out.WindowReason, err = missingModelWindow(ctx, idx, coreReq, binding, req.MaxBytes, snapshot)
		if err != nil {
			return empty, err
		}
	}

	if req.Action == "get" {
		out.Total = packet.TotalMatches
		for _, e := range entries(a.catalog) {
			if e.ID == req.ID {
				e.ResourceURI = ResourceURI(project.Key, snapshot, e.ID)
				out.Entries = append(out.Entries, e)
			}
		}
	}
	if err = session.Recheck(ctx); err != nil {
		return empty, err
	}
	rootAgain, err := readRootLock(project.RootPath)
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(rootAgain, a.rootBytes) {
		return empty, fail(Stale)
	}
	// Metadata is freshly source-authenticated too, not merely cached by C03.
	if _, err = knowledge.ObserveSource(ctx, r.TrustRuntime(), a.resolution, a.raw, binding.SourceID); err != nil {
		return empty, err
	}
	if !fit(&out, req.MaxBytes) {
		return empty, fail(Budget)
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	return out, nil
}

func normalize(r *Request) error {
	switch r.Action {
	case "discover", "search", "get", "plan":
	default:
		return fail(Invalid)
	}
	if r.Cursor != "" {
		return fail(Invalid)
	}
	if r.Limit == 0 {
		r.Limit = 8
	}
	if r.MaxRecords == 0 {
		r.MaxRecords = 64
	}
	if r.MaxBytes == 0 {
		r.MaxBytes = 32768
	}
	if r.MaxExcerptBytes == 0 {
		r.MaxExcerptBytes = 512
	}
	if r.Limit < 1 || r.Limit > 16 || r.MaxRecords < 1 || r.MaxRecords > 256 || r.MaxBytes < 1 || r.MaxBytes > 32768 || r.MaxExcerptBytes < 1 || r.MaxExcerptBytes > 2048 || len(r.Required) > 16 {
		return fail(Invalid)
	}
	for _, s := range append([]string{r.ID, r.Kind, r.Path, r.Text, r.CatalogPath}, r.Required...) {
		if len(s) > 256 || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return fail(Invalid)
		}
	}
	if r.Kind != "" && r.Kind != "block" && r.Kind != "skill" && r.Kind != "resource" && r.Kind != "path" {
		return fail(Invalid)
	}
	if r.Action == "get" && r.ID == "" {
		return fail(Invalid)
	}
	if r.Snapshot != "" && (len(r.Snapshot) != 71 || !strings.HasPrefix(r.Snapshot, "sha256:")) {
		return fail(Invalid)
	}
	return nil
}

func entries(d knowledge.Catalog) []resultdto.ContextEntry {
	out := make([]resultdto.ContextEntry, 0, len(d.Items)*2)
	anchors := map[string]string{}
	for _, it := range d.Items {
		out = append(out, resultdto.ContextEntry{ID: it.ID, Kind: it.Kind, SourceID: it.SourceID, Path: it.SourcePath})
		key := it.SourceID + "\x00" + it.SourcePath
		if _, ok := anchors[key]; ok {
			continue
		}
		anchors[key] = it.ID
		h := sha256.Sum256([]byte(key))
		id := strings.Split(it.SourceID, ":")[0] + ":path:p-" + hex.EncodeToString(h[:])
		out = append(out, resultdto.ContextEntry{ID: id, Kind: "path", SourceID: it.SourceID, Path: it.SourcePath})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func requestBinding(req Request, snapshot string) string {
	req.Snapshot = ""
	b, _ := json.Marshal(struct {
		Snapshot string
		Request  Request
	}{snapshot, req})
	return evidencecas.Digest(b)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	if len(s) == 0 || len(s) > 8192 {
		return c, fail(Invalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, fail(Invalid)
	}
	if err = canonicaljson.DecodeStrict(raw, &c); err != nil {
		return c, fail(Invalid)
	}
	if c.Version != "tplaiter.dev/context-cursor/v1" || c.Offset < 1 || c.Offset > 1024 || (c.Request.Action != "discover" && c.Request.Action != "search") {
		return c, fail(Invalid)
	}
	if err = normalize(&c.Request); err != nil {
		return c, err
	}
	return c, nil
}

func reflectEmpty(r Request) bool { b, _ := json.Marshal(r); return string(b) == `{"action":""}` }

func fit(out *resultdto.ContextData, maxBytes int) bool {
	for range 32 {
		b, err := json.Marshal(out)
		if err != nil {
			return false
		}
		if len(b) == out.Bytes {
			return out.Bytes <= maxBytes
		}
		out.Bytes = len(b)
	}
	return false
}

func ResourceURI(key, snapshot, id string) string {
	// RFC6570 simple variables encode reserved colons; PathEscape alone leaves
	// them literal and consequently fails the actual MCP template matcher.
	escape := func(s string) string { return strings.ReplaceAll(url.PathEscape(s), ":", "%3A") }
	return "tplaiter://context/" + escape(key) + "/" + escape(snapshot) + "/" + escape(id)
}

func ParseResourceURI(uri string) (key, snapshot, id string, err error) {
	u, e := url.Parse(uri)
	if e != nil || u.Scheme != "tplaiter" || u.Host != "context" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", "", fail(Invalid)
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(parts) != 3 {
		return "", "", "", fail(Invalid)
	}
	for i := range parts {
		parts[i], e = url.PathUnescape(parts[i])
		if e != nil || parts[i] == "" || strings.ContainsAny(parts[i], "/\\\x00\r\n") {
			return "", "", "", fail(Invalid)
		}
	}
	return parts[0], parts[1], parts[2], nil
}

// Code retains typed core diagnostics; transport messages never include host
// paths, raw trust material, source contents or arbitrary child stderr.
func Code(err error) string {
	var f *Error
	if errors.As(err, &f) {
		return f.Code
	}
	var w *contextwindow.Error
	if errors.As(err, &w) {
		return w.Code
	}
	var c *contextindex.Error
	if errors.As(err, &c) {
		return c.Code
	}
	var k *knowledge.Error
	if errors.As(err, &k) {
		return k.Code
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "CONTEXT_CANCELLED"
	}
	return "CONTEXT_AUTHENTICATION_FAILED"
}
