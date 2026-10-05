package providerclient

import (
	"bytes"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

type catalogParts struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	ID         string            `json:"id"`
	Version    string            `json:"version"`
	Sources    []json.RawMessage `json:"sources"`
	Items      []json.RawMessage `json:"items"`
	Edges      []json.RawMessage `json:"edges"`
}

func parts(raw []byte) (catalogParts, error) {
	var p catalogParts
	// C01 nullable defaults are intentionally opaque here. Each entire object is
	// compared to a validated frozen object, then the merged bytes use C01 Decode.
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || len(envelope) != 7 || !jsonEqual(raw, raw) || !required(raw, "apiVersion", "kind", "id", "version", "sources", "items", "edges") || json.Unmarshal(raw, &p) != nil || p.Sources == nil || p.Items == nil || p.Edges == nil {
		return p, failure("SESSION_WIRE", nil)
	}
	return p, nil
}

func objectString(raw []byte, key string) string {
	var m map[string]json.RawMessage
	var s string
	if json.Unmarshal(raw, &m) == nil {
		_ = json.Unmarshal(m[key], &s)
	}
	return s
}

func containsObject(objects []json.RawMessage, id string, raw []byte) bool {
	if id == "" {
		return false
	}
	for _, obj := range objects {
		if objectString(obj, "id") == id {
			return jsonEqual(obj, raw)
		}
	}
	return false
}

func edgeKey(raw []byte) string {
	return objectString(raw, "from") + "\x00" + objectString(raw, "to") + "\x00" + objectString(raw, "layer") + "\x00" + objectString(raw, "relation")
}

func containsEdge(edges []json.RawMessage, key string, raw []byte) bool {
	for _, obj := range edges {
		if edgeKey(obj) == key {
			return jsonEqual(obj, raw)
		}
	}
	return false
}

func containsID(p catalogParts, id string) bool {
	for _, xs := range [][]json.RawMessage{p.Sources, p.Items} {
		for _, obj := range xs {
			if objectString(obj, "id") == id {
				return true
			}
		}
	}
	return false
}

// CatalogReceipt is immutable local wire evidence. Its zero value is invalid;
// JSON decoding cannot manufacture a receipt. Accessors return owned copies.
// Content pins declare expected bodies; only ContentReceipt records a read.
type CatalogReceipt struct {
	session        *Session
	raw            []byte
	binding        Binding
	sources, items []json.RawMessage
	descriptors    []SourceDescriptor
}

func (r *CatalogReceipt) Bytes() []byte {
	if r == nil {
		return nil
	}
	return copyRaw(r.raw)
}
func (r *CatalogReceipt) Binding() Binding {
	if r == nil {
		return Binding{}
	}
	return cloneBinding(r.binding)
}
func (r *CatalogReceipt) Sources() []json.RawMessage {
	if r == nil {
		return nil
	}
	return cloneObjects(r.sources)
}
func (r *CatalogReceipt) Items() []json.RawMessage {
	if r == nil {
		return nil
	}
	return cloneObjects(r.items)
}
func (r *CatalogReceipt) Descriptors() []SourceDescriptor {
	if r == nil {
		return nil
	}
	return cloneDescriptors(r.descriptors)
}

// ContentReceipt records a pinned read on the catalog's original connection.
type ContentReceipt struct {
	catalog *CatalogReceipt
	asset   AssetDescriptor
	body    []byte
}

func (r *ContentReceipt) Bytes() []byte {
	if r == nil {
		return nil
	}
	return copyRaw(r.body)
}
func (r *ContentReceipt) Asset() AssetDescriptor {
	if r == nil {
		return AssetDescriptor{}
	}
	return r.asset
}
func (r *ContentReceipt) Catalog() *CatalogReceipt {
	if r == nil {
		return nil
	}
	return r.catalog
}

func cloneObjects(xs []json.RawMessage) []json.RawMessage {
	if xs == nil {
		return nil
	}
	out := make([]json.RawMessage, len(xs))
	for i := range xs {
		out[i] = copyRaw(xs[i])
	}
	return out
}

type catalogCapture struct {
	headers               map[string]json.RawMessage
	sources, items, edges []json.RawMessage
	seenEdges             map[string]bool
	bytes, pages          int
	receipt               *CatalogReceipt
}

func (c *catalogCapture) observe(result []byte) error {
	var envelope struct {
		Catalog json.RawMessage `json:"catalog"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return failure("SESSION_WIRE", nil)
	}
	if len(envelope.Catalog) > knowledge.MaxBytes-c.bytes || c.pages >= 128 {
		return failure("SESSION_BOUNDS", nil)
	}
	c.bytes += len(envelope.Catalog)
	c.pages++
	p, err := parts(envelope.Catalog)
	if err != nil {
		return err
	}
	if c.headers == nil {
		c.headers = make(map[string]json.RawMessage)
		if json.Unmarshal(envelope.Catalog, &c.headers) != nil {
			return failure("SESSION_WIRE", nil)
		}
		for _, key := range []string{"sources", "items", "edges"} {
			delete(c.headers, key)
		}
		c.seenEdges = make(map[string]bool)
	}
	c.sources = append(c.sources, p.Sources...)
	c.items = append(c.items, p.Items...)
	for _, edge := range p.Edges {
		key := edgeKey(edge)
		if !c.seenEdges[key] {
			c.seenEdges[key] = true
			c.edges = append(c.edges, edge)
		}
	}
	return nil
}

// Assemble only captured raw values in the wire-defined complete-catalog field
// order. Compact removes wire whitespace; it never reserializes C01 objects,
// defaults, strings, numbers or object member order.
func (c *catalogCapture) finish(s *Session, b Binding) (*CatalogReceipt, error) {
	if c.headers == nil {
		return nil, failure("SESSION_PARTIAL", nil)
	}
	var raw bytes.Buffer
	raw.WriteByte('{')
	for i, key := range []string{"apiVersion", "kind", "id", "version", "sources", "items", "edges"} {
		if i != 0 {
			raw.WriteByte(',')
		}
		raw.WriteString(`"` + key + `":`)
		if i < 4 {
			raw.Write(c.headers[key])
			continue
		}
		var objects []json.RawMessage
		switch key {
		case "sources":
			objects = c.sources
		case "items":
			objects = c.items
		case "edges":
			objects = c.edges
		}
		raw.WriteByte('[')
		for j, obj := range objects {
			if j != 0 {
				raw.WriteByte(',')
			}
			raw.Write(obj)
		}
		raw.WriteByte(']')
	}
	raw.WriteByte('}')
	if raw.Len() > knowledge.MaxBytes {
		return nil, failure("SESSION_BOUNDS", nil)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw.Bytes()) != nil {
		return nil, failure("SESSION_WIRE", nil)
	}
	if digest(compact.Bytes()) != b.CatalogSHA256 {
		return nil, failure("SESSION_CATALOG_BINDING", nil)
	}
	r := &CatalogReceipt{session: s, raw: copyRaw(compact.Bytes()), binding: cloneBinding(s.binding), sources: cloneObjects(c.sources), items: cloneObjects(c.items)}
	for _, source := range s.discovered {
		for _, captured := range c.sources {
			if objectString(captured, "id") == source.ID {
				r.descriptors = append(r.descriptors, cloneDescriptors([]SourceDescriptor{source})[0])
				break
			}
		}
	}
	return r, nil
}

func cloneBinding(b Binding) Binding {
	b.CatalogDigest = copyRaw(b.CatalogDigest)
	b.ScopeDigest = copyRaw(b.ScopeDigest)
	b.QueryDigest = copyRaw(b.QueryDigest)
	return b
}

func cloneDescriptors(xs []SourceDescriptor) []SourceDescriptor {
	if xs == nil {
		return nil
	}
	out := make([]SourceDescriptor, len(xs))
	copy(out, xs)
	for i := range out {
		out[i].Assets = append([]AssetDescriptor(nil), xs[i].Assets...)
		out[i].Capabilities = append([]string(nil), xs[i].Capabilities...)
		out[i].Unresolved = append([]string(nil), xs[i].Unresolved...)
	}
	return out
}
