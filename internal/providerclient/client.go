// Package providerclient consumes the existing local-provider.session/v1 wire.
// Its injected transport and frozen metadata provide no organization authority.
package providerclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

const (
	APIVersion            = "local-provider.session/v1"
	DescriptorVersion     = "local-provider.descriptor/v1"
	KnowledgeSchemaSHA256 = "sha256:b5febb8f5454254771eae7c5624a1994971517acb76b56b148e610b7853cbad6"
	LocalPrototype        = "local-user-approved-uncertified"
)

type Error struct {
	Code     string
	PeerCode string
	cause    error
}

func (e *Error) Error() string               { return e.Code }
func (e *Error) Unwrap() error               { return e.cause }
func failure(code string, cause error) error { return &Error{Code: code, cause: cause} }

// Limits are host bounds, not producer capabilities or token accounting.
type Limits struct {
	FrameBytes, TotalBytes, Pages int
	Timeout                       time.Duration
}

func bounded(l Limits) (Limits, error) {
	if l.FrameBytes == 0 {
		l.FrameBytes = 32768
	}
	if l.TotalBytes == 0 {
		l.TotalBytes = 2 << 20
	}
	if l.Pages == 0 {
		l.Pages = 128
	}
	if l.Timeout == 0 {
		l.Timeout = 2 * time.Second
	}
	if l.FrameBytes < 512 || l.FrameBytes > 32768 || l.TotalBytes < l.FrameBytes || l.TotalBytes > 2<<20 || l.Pages < 1 || l.Pages > 128 || l.Timeout <= 0 || l.Timeout > 2*time.Second {
		return l, failure("SESSION_LIMITS", nil)
	}
	return l, nil
}

// Budget uses the existing closed request vocabulary. Zero means producer default.
type Budget struct {
	ResponseBytes int  `json:"responseBytes,omitempty"`
	MetadataBytes int  `json:"metadataBytes,omitempty"`
	SourceBytes   int  `json:"sourceBytes,omitempty"`
	StrictTokens  bool `json:"strictTokens,omitempty"`
}

// Query is fixed by the host before handshake and cannot be changed mid-session.
// Knowledge never sends assetId/path or an arbitrary operation.
type Query struct {
	SourceID, Pin string
	PageSources   int
	DeadlineMS    int
	Budget        Budget
}

func validQuery(q Query) bool {
	return q.PageSources >= 1 && q.PageSources <= 128 && q.DeadlineMS >= 0 && q.DeadlineMS <= 2000 && len(q.SourceID) <= 256 && len(q.Pin) <= 256 && q.Budget.ResponseBytes >= 0 && q.Budget.ResponseBytes <= 32768 && (q.Budget.ResponseBytes == 0 || q.Budget.ResponseBytes >= 512) && q.Budget.MetadataBytes >= 0 && q.Budget.MetadataBytes <= 16384 && q.Budget.SourceBytes >= 0 && q.Budget.SourceBytes <= 8192 && !q.Budget.StrictTokens
}

// HostBinding is independently frozen public metadata from the approved producer
// receipt. It is not a trust permit. Digest JSON is kept opaque: the client never
// guesses private hash domains/serialization or manufactures producer cursors.
type HostBinding struct {
	HandshakeResultSHA256                   string
	KnowledgeSchemaSHA256                   string
	CatalogSHA256                           string
	CatalogJSON                             []byte
	CatalogDigest, ScopeDigest, QueryDigest json.RawMessage
	SuccessStatus                           string
}
type Binding struct {
	HandshakeResultSHA256, CatalogSHA256, SchemaSHA256 string
	CatalogDigest, ScopeDigest, QueryDigest            json.RawMessage
}

type request struct {
	Version              string   `json:"version"`
	ID                   string   `json:"id,omitempty"`
	Op                   string   `json:"op"`
	SchemaVersions       []string `json:"schemaVersions,omitempty"`
	RequiredOperations   []string `json:"requiredOperations,omitempty"`
	RequiredCapabilities []string `json:"requiredCapabilities,omitempty"`
	SourceID             string   `json:"sourceId,omitempty"`
	AssetID              string   `json:"assetId,omitempty"`
	Pin                  string   `json:"pin,omitempty"`
	Path                 string   `json:"path,omitempty"`
	Projection           string   `json:"projection,omitempty"`
	DeadlineMS           int      `json:"deadlineMs,omitempty"`
	Budget               *Budget  `json:"budget,omitempty"`
}
type response struct {
	Version string          `json:"version"`
	ID      string          `json:"id,omitempty"`
	Status  string          `json:"status"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
	Usage   json.RawMessage `json:"usage"`
}
type page struct {
	CatalogDigest      json.RawMessage `json:"catalogDigest"`
	ScopeDigest        json.RawMessage `json:"scopeDigest"`
	QueryDigest        json.RawMessage `json:"queryDigest"`
	Offset             int             `json:"offset"`
	TotalSources       int             `json:"totalSources"`
	Complete           bool            `json:"complete"`
	ExternalReferences []string        `json:"externalReferences"`
	Catalog            json.RawMessage `json:"catalog"`
	NextCursor         string          `json:"nextCursor,omitempty"`
}

// Session has no caller-set capability flags. Only OpenLocal establishes it;
// a zero value cannot read. ReadCatalog is one-use; Close may interrupt it.
type Session struct {
	conn         net.Conn
	reader       *bufio.Reader
	limits       Limits
	query        Query
	host         HostBinding
	expected     catalogParts
	binding      Binding
	used, closed atomic.Bool
	bytes        int
	dynamic      bool
	discovered   []SourceDescriptor
	hello        Description
	busy         atomic.Bool
	frames       int
	sequence     int
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func pin(s string) bool        { return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(s) }
func jsonEqual(a, b []byte) bool {
	x, e := canonicaljson.Canonicalize(a)
	if e != nil {
		return false
	}
	y, e := canonicaljson.Canonicalize(b)
	return e == nil && bytes.Equal(x, y)
}

func strict(raw []byte, dst any) error {
	if canonicaljson.DecodeStrict(raw, dst) != nil {
		return failure("SESSION_WIRE", nil)
	}
	return nil
}

// strictOpaque validates the complete JSON syntax first, then checks the closed
// envelope without rejecting C01's permitted nullable defaults inside catalog.
func strictOpaque(raw []byte, dst any, opaque ...string) error {
	if !jsonEqual(raw, raw) {
		return failure("SESSION_WIRE", nil)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return failure("SESSION_WIRE", nil)
	}
	for _, key := range opaque {
		if value, ok := obj[key]; ok {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return failure("SESSION_WIRE", nil)
			}
			obj[key] = json.RawMessage(`{}`)
		}
	}
	sanitized, err := json.Marshal(obj)
	if err != nil || strict(sanitized, dst) != nil || json.Unmarshal(raw, dst) != nil {
		return failure("SESSION_WIRE", nil)
	}
	return nil
}

func required(raw []byte, keys ...string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	for _, key := range keys {
		if _, ok := obj[key]; !ok {
			return false
		}
	}
	return true
}
func copyRaw(raw []byte) json.RawMessage { return append(json.RawMessage(nil), raw...) }

// OpenLocal takes exclusive ownership of hostConn even on failure. The host
// supplies the real producer receipt's frozen result/catalog/digest bytes. No
// production authentication, command, credential or transport is constructed.
func OpenLocal(ctx context.Context, hostConn net.Conn, host HostBinding, query Query, limits Limits) (session *Session, err error) {
	if hostConn == nil {
		return nil, failure("SESSION_TRANSPORT", nil)
	}
	s := &Session{conn: hostConn, reader: bufio.NewReaderSize(hostConn, 4096), query: query}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	s.limits, err = bounded(limits)
	if err != nil {
		return nil, err
	}
	if query.Budget.ResponseBytes > 0 && query.Budget.ResponseBytes < s.limits.FrameBytes {
		s.limits.FrameBytes = query.Budget.ResponseBytes
	}
	if ctx == nil || !validQuery(query) || !pin(host.HandshakeResultSHA256) || host.KnowledgeSchemaSHA256 != KnowledgeSchemaSHA256 || !pin(host.CatalogSHA256) || len(host.CatalogJSON) > knowledge.MaxBytes || digest(host.CatalogJSON) != host.CatalogSHA256 || host.SuccessStatus == "" || len(host.SuccessStatus) > 32 {
		return nil, failure("SESSION_HOST_BINDING", nil)
	}
	// All caller buffers are copied before admitting the session.
	host.CatalogJSON = copyRaw(host.CatalogJSON)
	host.CatalogDigest = copyRaw(host.CatalogDigest)
	host.ScopeDigest = copyRaw(host.ScopeDigest)
	host.QueryDigest = copyRaw(host.QueryDigest)
	for _, d := range []json.RawMessage{host.CatalogDigest, host.ScopeDigest, host.QueryDigest} {
		if len(d) == 0 || len(d) > 1024 || !jsonEqual(d, d) || bytes.Equal(bytes.TrimSpace(d), []byte("null")) {
			return nil, failure("SESSION_HOST_BINDING", nil)
		}
	}
	if _, err = knowledge.Decode(host.CatalogJSON); err != nil {
		return nil, err
	}
	s.expected, err = parts(host.CatalogJSON)
	if err != nil {
		return nil, err
	}
	if len(s.expected.Sources) == 0 {
		return nil, failure("SESSION_HOST_BINDING", nil)
	}
	if query.SourceID != "" {
		if len(s.expected.Sources) != 1 || objectString(s.expected.Sources[0], "id") != query.SourceID {
			return nil, failure("SESSION_HOST_BINDING", nil)
		}
	}
	s.host = host
	finish, err := s.deadline(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	r, err := s.exchange(ctx, request{Version: APIVersion, ID: "hello", Op: "handshake", SchemaVersions: []string{DescriptorVersion}, RequiredOperations: []string{"describe", "knowledge"}, RequiredCapabilities: []string{"local-curated-read"}, DeadlineMS: query.DeadlineMS, Budget: &query.Budget})
	if err != nil {
		return nil, err
	}
	if digest(r.Result) != host.HandshakeResultSHA256 {
		return nil, failure("SESSION_DESCRIPTOR_PIN", nil)
	}
	// The frozen result binds all advertised provider/limits/capability metadata.
	// Decode only documented negotiation fields; unknown nested provider metadata
	// cannot become permissions. Its exact schema is checked by the producer receipt.
	var hello map[string]json.RawMessage
	if strict(r.Result, &hello) != nil || !required(r.Result, "provider", "schemaVersion", "limits", "sideEffectClasses", "unsupportedCapabilities") {
		return nil, failure("SESSION_NEGOTIATION", nil)
	}
	var schema string
	if json.Unmarshal(hello["schemaVersion"], &schema) != nil || schema != DescriptorVersion {
		return nil, failure("SESSION_VERSION", nil)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	s.binding = Binding{HandshakeResultSHA256: host.HandshakeResultSHA256, CatalogSHA256: host.CatalogSHA256, SchemaSHA256: host.KnowledgeSchemaSHA256, CatalogDigest: copyRaw(host.CatalogDigest), ScopeDigest: copyRaw(host.ScopeDigest), QueryDigest: copyRaw(host.QueryDigest)}
	return s, nil
}
func (s *Session) Qualification() string    { return LocalPrototype }
func (s *Session) RequireProduction() error { return failure("SESSION_PRODUCTION_UNQUALIFIED", nil) }

func (s *Session) Close() error {
	if s == nil || s.conn == nil || s.closed.Swap(true) {
		return nil
	}
	return s.conn.Close()
}

func (s *Session) deadline(ctx context.Context) (func(), error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	end := time.Now().Add(s.limits.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(end) {
		end = d
	}
	if e := s.conn.SetDeadline(end); e != nil {
		return nil, failure("SESSION_TRANSPORT", e)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	return func() { stop() }, nil
}

func (s *Session) exchange(ctx context.Context, q request) (response, error) {
	var r response
	if s.frames >= 256 {
		return r, failure("SESSION_BOUNDS", nil)
	}
	s.frames++
	if err := ctx.Err(); err != nil {
		return r, err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return r, failure("SESSION_WIRE", nil)
	}
	if err = s.write(raw); err != nil {
		return r, s.ioError(ctx, err)
	}
	raw, err = s.read()
	if err != nil {
		return r, s.ioError(ctx, err)
	}
	if strictOpaque(raw, &r, "result", "error", "usage") != nil || !required(raw, "version", "id", "status", "usage") || (len(r.Result) == 0) == (len(r.Error) == 0) {
		return r, failure("SESSION_WIRE", nil)
	}
	if r.Version != APIVersion {
		return r, failure("SESSION_VERSION", nil)
	}
	if r.ID != q.ID {
		return r, failure("SESSION_SCOPE", nil)
	}
	var usage map[string]json.RawMessage
	if strict(r.Usage, &usage) != nil || usage == nil {
		return r, failure("SESSION_WIRE", nil)
	}
	if len(r.Error) > 0 {
		var refusal struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if strict(r.Error, &refusal) != nil || !required(r.Error, "code", "message") || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(refusal.Code) {
			return r, failure("SESSION_WIRE", nil)
		}
		return r, &Error{Code: "SESSION_REFUSED", PeerCode: refusal.Code}
	}
	if r.Status != s.host.SuccessStatus {
		return r, failure("SESSION_WIRE", nil)
	}
	return r, nil
}

func (s *Session) ioError(ctx context.Context, err error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var t net.Error
	if errors.As(err, &t) && t.Timeout() {
		return failure("SESSION_DEADLINE", context.DeadlineExceeded)
	}
	var p *Error
	if errors.As(err, &p) {
		return err
	}
	return failure("SESSION_IO", err)
}

func (s *Session) reserve(n int) error {
	if n < 0 || n > s.limits.TotalBytes-s.bytes {
		return failure("SESSION_BOUNDS", nil)
	}
	s.bytes += n
	return nil
}

func (s *Session) write(raw []byte) error {
	if len(raw)+1 > 4096 {
		return failure("SESSION_BOUNDS", nil)
	}
	raw = append(raw, '\n')
	packet := raw
	if e := s.reserve(len(packet)); e != nil {
		return e
	}
	for len(packet) > 0 {
		n, e := s.conn.Write(packet)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(packet) {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

func (s *Session) read() ([]byte, error) {
	raw := make([]byte, 0, 4096)
	for {
		part, e := s.reader.ReadSlice('\n')
		if err := s.reserve(len(part)); err != nil {
			return nil, err
		}
		if len(part) > s.limits.FrameBytes-len(raw) {
			return nil, failure("SESSION_BOUNDS", nil)
		}
		raw = append(raw, part...)
		if e == nil {
			if len(raw) <= 1 {
				return nil, failure("SESSION_WIRE", nil)
			}
			return raw[:len(raw)-1], nil
		}
		if !errors.Is(e, bufio.ErrBufferFull) {
			return nil, e
		}
	}
}

// ReadCatalog merges complete source pages and checks all objects against the
// independently frozen public C01 catalog. Producer digest fields are compared
// to receipt pins, never recomputed using a guessed private serialization.
func (s *Session) ReadCatalog(ctx context.Context) (catalog knowledge.Catalog, binding Binding, err error) {
	if s == nil || s.conn == nil || ctx == nil || s.closed.Load() || s.used.Swap(true) {
		return catalog, binding, failure("SESSION_LIFETIME", nil)
	}
	if !s.busy.CompareAndSwap(false, true) {
		return catalog, binding, failure("SESSION_BUSY", nil)
	}
	defer s.busy.Store(false)
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	finish, err := s.deadline(ctx)
	if err != nil {
		return catalog, binding, err
	}
	defer finish()
	if s.dynamic {
		return s.readLiveCatalog(ctx)
	}
	merged := s.expected
	merged.Sources = nil
	merged.Items = nil
	merged.Edges = nil
	seenSources := map[string]bool{}
	seenItems := map[string]bool{}
	seenEdges := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	offset := 0
	for n := 0; n < s.limits.Pages; n++ {
		projection := "page:" + strconv.Itoa(s.query.PageSources)
		if cursor != "" {
			projection += ":" + cursor
		}
		r, e := s.exchange(ctx, request{Version: APIVersion, ID: "knowledge-" + strconv.Itoa(n+1), Op: "knowledge", SourceID: s.query.SourceID, Pin: s.query.Pin, Projection: projection, DeadlineMS: s.query.DeadlineMS, Budget: &s.query.Budget})
		if e != nil {
			return catalog, binding, e
		}
		var p page
		if strictOpaque(r.Result, &p, "catalog") != nil || !required(r.Result, "catalogDigest", "scopeDigest", "queryDigest", "offset", "totalSources", "complete", "externalReferences", "catalog") {
			return catalog, binding, failure("SESSION_WIRE", nil)
		}
		if !jsonEqual(p.CatalogDigest, s.host.CatalogDigest) || !jsonEqual(p.ScopeDigest, s.host.ScopeDigest) || !jsonEqual(p.QueryDigest, s.host.QueryDigest) {
			return catalog, binding, failure("SESSION_SCOPE", nil)
		}
		if p.Offset != offset || p.TotalSources != len(s.expected.Sources) || p.ExternalReferences == nil {
			return catalog, binding, failure("SESSION_CURSOR", nil)
		}
		part, e := parts(p.Catalog)
		if e != nil {
			return catalog, binding, e
		}
		if part.APIVersion != merged.APIVersion || part.Kind != merged.Kind || part.ID != merged.ID || part.Version != merged.Version {
			return catalog, binding, failure("SESSION_CATALOG_BINDING", nil)
		}
		if len(part.Sources) == 0 || len(part.Sources) > s.query.PageSources || len(part.Sources) > len(s.expected.Sources)-offset {
			return catalog, binding, failure("SESSION_BOUNDS", nil)
		}
		pageSources := map[string]bool{}
		for _, obj := range part.Sources {
			id := objectString(obj, "id")
			if seenSources[id] || !containsObject(s.expected.Sources, id, obj) {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			seenSources[id] = true
			pageSources[id] = true
			merged.Sources = append(merged.Sources, obj)
		}
		for _, obj := range part.Items {
			id := objectString(obj, "id")
			if seenItems[id] || !pageSources[objectString(obj, "sourceId")] || !containsObject(s.expected.Items, id, obj) {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			seenItems[id] = true
			merged.Items = append(merged.Items, obj)
		}
		for _, obj := range s.expected.Items {
			if pageSources[objectString(obj, "sourceId")] && !seenItems[objectString(obj, "id")] {
				return catalog, binding, failure("SESSION_PARTIAL", nil)
			}
		}
		pageIDs := make(map[string]bool)
		for id := range pageSources {
			pageIDs[id] = true
		}
		for _, obj := range part.Items {
			pageIDs[objectString(obj, "id")] = true
		}
		pageEdges := make(map[string]bool)
		for _, obj := range part.Edges {
			key := edgeKey(obj)
			if pageEdges[key] {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			pageEdges[key] = true
			if !pageIDs[objectString(obj, "from")] && !pageIDs[objectString(obj, "to")] {
				return catalog, binding, failure("SESSION_SCOPE", nil)
			}
			if !containsEdge(s.expected.Edges, key, obj) {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			if !seenEdges[key] {
				seenEdges[key] = true
				merged.Edges = append(merged.Edges, obj)
			}
		}
		for _, ref := range p.ExternalReferences {
			if !containsID(s.expected, ref) {
				return catalog, binding, failure("SESSION_PARTIAL", nil)
			}
		}
		offset += len(part.Sources)
		if p.Complete {
			if p.NextCursor != "" || offset != len(s.expected.Sources) || len(merged.Items) != len(s.expected.Items) || len(merged.Edges) != len(s.expected.Edges) {
				return catalog, binding, failure("SESSION_PARTIAL", nil)
			}
			// Empty arrays stay explicit even when a catalog has no items/edges.
			if merged.Items == nil {
				merged.Items = []json.RawMessage{}
			}
			if merged.Edges == nil {
				merged.Edges = []json.RawMessage{}
			}
			raw, e := json.Marshal(merged)
			if e != nil || len(raw) > knowledge.MaxBytes {
				return catalog, binding, failure("SESSION_BOUNDS", nil)
			}
			// Bind the actual assembled compact wire bytes, retaining object
			// and array order. Semantic membership cannot prove this digest.
			if digest(raw) != s.host.CatalogSHA256 {
				return catalog, binding, failure("SESSION_CATALOG_BINDING", nil)
			}
			decoded, e := knowledge.Decode(raw)
			if e != nil {
				return catalog, binding, e
			}
			if e = ctx.Err(); e != nil {
				return catalog, binding, e
			}
			b := s.binding
			b.CatalogDigest = copyRaw(b.CatalogDigest)
			b.ScopeDigest = copyRaw(b.ScopeDigest)
			b.QueryDigest = copyRaw(b.QueryDigest)
			return decoded, b, nil
		}
		if offset == len(s.expected.Sources) || !validCursor(p.NextCursor) || seenCursors[p.NextCursor] {
			return catalog, binding, failure("SESSION_CURSOR", nil)
		}
		cursor = p.NextCursor
		seenCursors[cursor] = true
	}
	return catalog, binding, failure("SESSION_BOUNDS", nil)
}

func validCursor(s string) bool {
	if len(s) == 0 || len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
