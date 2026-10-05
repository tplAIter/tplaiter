package providerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/knowledge"
)

// Description is observed local negotiation metadata, never a trust permit.
type Description struct {
	Provider struct {
		ID             string   `json:"providerId"`
		Operations     []string `json:"operations"`
		Capabilities   []string `json:"capabilities"`
		SnapshotDigest string   `json:"snapshotDigest"`
		Evidence       string   `json:"evidence"`
		Qualification  string   `json:"qualification"`
	} `json:"provider"`
	SchemaVersion string `json:"schemaVersion"`
	Limits        struct {
		DeadlineMS    int `json:"deadlineMs"`
		FrameBytes    int `json:"frameBytes"`
		Frames        int `json:"frames"`
		MetadataBytes int `json:"metadataBytes"`
		QueuedFrames  int `json:"queuedFrames"`
		ResponseBytes int `json:"responseBytes"`
		SourceBytes   int `json:"sourceBytes"`
	} `json:"limits"`
	SideEffectClasses       []string `json:"sideEffectClasses"`
	UnsupportedCapabilities []string `json:"unsupportedCapabilities"`
}
type Digest struct {
	Algorithm string `json:"algorithm"`
	Domain    string `json:"domain"`
	Hex       string `json:"hex"`
}
type AssetDescriptor struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Anchor struct {
		SourceID   string `json:"sourceId"`
		Revision   string `json:"revision"`
		Path       string `json:"path"`
		BlobDigest Digest `json:"blobDigest"`
	} `json:"anchor"`
	Bytes            int    `json:"bytes"`
	DescriptorDigest Digest `json:"descriptorDigest"`
}
type SourceDescriptor struct {
	ID             string            `json:"id"`
	RepositoryID   int               `json:"repositoryId"`
	RootRef        string            `json:"rootRef"`
	Revision       string            `json:"revision,omitempty"`
	GitTreeOID     string            `json:"gitTreeOid,omitempty"`
	State          string            `json:"state"`
	Category       string            `json:"category"`
	Summary        string            `json:"summary"`
	Capabilities   []string          `json:"capabilities"`
	Assets         []AssetDescriptor `json:"assets"`
	Classification string            `json:"classification"`
	SourceTrust    string            `json:"sourceTrust"`
	Unresolved     []string          `json:"unresolved"`
}

func includes(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func copyJSON[T any](v T) T {
	raw, _ := json.Marshal(v)
	var result T
	_ = json.Unmarshal(raw, &result)
	return result
}

func (s *Session) Description() Description {
	if s == nil {
		return Description{}
	}
	return copyJSON(s.hello)
}

func (s *Session) Sources() []SourceDescriptor {
	if s == nil {
		return nil
	}
	return copyJSON(s.discovered)
}

// Open learns per-run pins only from the host-owned local connection. This is
// deliberately uncertified local admission, not organization authentication.
func Open(ctx context.Context, conn net.Conn, query Query, limits Limits) (session *Session, err error) {
	if conn == nil {
		return nil, failure("SESSION_TRANSPORT", nil)
	}
	s := &Session{conn: conn, reader: bufio.NewReaderSize(conn, 4096), query: query, dynamic: true, host: HostBinding{SuccessStatus: "ok"}}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	s.limits, err = bounded(limits)
	if err != nil {
		return nil, err
	}
	if ctx == nil || !validQuery(query) {
		return nil, failure("SESSION_HOST_BINDING", nil)
	}
	if query.Budget.ResponseBytes > 0 && query.Budget.ResponseBytes < s.limits.FrameBytes {
		s.limits.FrameBytes = query.Budget.ResponseBytes
	}
	finish, err := s.deadline(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	requiredOps := []string{"describe", "catalog", "read", "knowledge"}
	r, err := s.exchange(ctx, request{Version: APIVersion, ID: "hello", Op: "handshake", SchemaVersions: []string{DescriptorVersion}, RequiredOperations: requiredOps, RequiredCapabilities: []string{"local-curated-read"}, DeadlineMS: query.DeadlineMS, Budget: &query.Budget})
	if err != nil {
		return nil, err
	}
	if strict(r.Result, &s.hello) != nil || s.hello.SchemaVersion != DescriptorVersion {
		return nil, failure("SESSION_NEGOTIATION", nil)
	}
	for _, op := range requiredOps {
		if !includes(s.hello.Provider.Operations, op) {
			return nil, failure("SESSION_NEGOTIATION", nil)
		}
	}
	if !includes(s.hello.Provider.Capabilities, "local-curated-read") || includes(s.hello.UnsupportedCapabilities, "local-curated-read") || !includes(s.hello.SideEffectClasses, "read-only-local") || s.hello.Provider.Qualification != LocalPrototype || !validSnapshot(s.hello.Provider.SnapshotDigest) {
		return nil, failure("SESSION_NEGOTIATION", nil)
	}
	l := s.hello.Limits
	if l.FrameBytes <= 0 || l.FrameBytes > 4096 || l.ResponseBytes <= 0 || l.ResponseBytes > 32768 || l.MetadataBytes <= 0 || l.MetadataBytes > 16384 || l.SourceBytes <= 0 || l.SourceBytes > 8192 || l.DeadlineMS <= 0 || l.DeadlineMS > 2000 || l.Frames < 3 || l.Frames > 256 || l.QueuedFrames != 0 {
		return nil, failure("SESSION_NEGOTIATION", nil)
	}
	if l.ResponseBytes < s.limits.FrameBytes {
		s.limits.FrameBytes = l.ResponseBytes
	}
	s.binding = Binding{HandshakeResultSHA256: digest(r.Result), SchemaSHA256: KnowledgeSchemaSHA256, ScopeDigest: jsonString(s.hello.Provider.SnapshotDigest)}
	r, err = s.exchange(ctx, request{Version: APIVersion, ID: "catalog", Op: "catalog", Projection: "full", Budget: &query.Budget, DeadlineMS: query.DeadlineMS})
	if err != nil {
		return nil, err
	}
	if strict(r.Result, &s.discovered) != nil || s.discovered == nil || len(s.discovered) > 128 {
		return nil, failure("SESSION_WIRE", nil)
	}
	seen := map[string]bool{}
	assets := map[string]bool{}
	for _, source := range s.discovered {
		if source.ID == "" || seen[source.ID] || source.Assets == nil {
			return nil, failure("SESSION_SCOPE", nil)
		}
		seen[source.ID] = true
		if source.State == "not-ready-empty" {
			if len(source.Assets) != 0 {
				return nil, failure("SESSION_SCOPE", nil)
			}
			continue
		}
		if source.State != "available-static" || !gitOID(source.Revision) || !gitOID(source.GitTreeOID) {
			return nil, failure("SESSION_SCOPE", nil)
		}
		paths := map[string]bool{}
		for _, a := range source.Assets {
			if a.ID == "" || assets[a.ID] || a.Kind != "static-document" || a.Anchor.SourceID != source.ID || a.Anchor.Revision != source.Revision || !safePath(a.Anchor.Path) || a.Bytes < 0 || a.Bytes > 65536 || a.Anchor.BlobDigest.Algorithm != "sha256" || a.Anchor.BlobDigest.Domain != "content-bytes" || !pin("sha256:"+a.Anchor.BlobDigest.Hex) || a.DescriptorDigest.Algorithm != "sha256" || !pin("sha256:"+a.DescriptorDigest.Hex) {
				return nil, failure("SESSION_SCOPE", nil)
			}
			// The current C01 mapping identifies an asset by source and path.
			// Distinct descriptor IDs cannot be collapsed into one item.
			if paths[a.Anchor.Path] {
				return nil, failure("SESSION_ASSET_AMBIGUITY", nil)
			}
			paths[a.Anchor.Path] = true
			assets[a.ID] = true
		}
	}
	if query.SourceID != "" {
		src, ok := s.source(query.SourceID)
		if !ok || src.State != "available-static" {
			return nil, failure("SESSION_SCOPE", nil)
		}
		if query.Pin != "" && query.Pin != src.Revision {
			return nil, failure("SESSION_CATALOG_PIN", nil)
		}
	} else if query.Pin != "" {
		return nil, failure("SESSION_SCOPE", nil)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}
func gitOID(s string) bool { return regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(s) }
func validSnapshot(s string) bool {
	return regexp.MustCompile(`^sha256:[a-zA-Z0-9._-]+:[0-9a-f]{64}$`).MatchString(s)
}

func safePath(s string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(s) && s != "" && s[0] != '/' && !regexp.MustCompile(`(^|/)\.\.?(/|$)|//`).MatchString(s)
}
func jsonString(s string) json.RawMessage { raw, _ := json.Marshal(s); return raw }
func (s *Session) source(id string) (SourceDescriptor, bool) {
	for _, src := range s.discovered {
		if src.ID == id {
			return src, true
		}
	}
	return SourceDescriptor{}, false
}

func (s *Session) wantedSources() int {
	n := 0
	for _, src := range s.discovered {
		if src.State == "available-static" && (s.query.SourceID == "" || s.query.SourceID == src.ID) {
			n++
		}
	}
	return n
}

func (s *Session) readLiveCatalog(ctx context.Context) (catalog knowledge.Catalog, binding Binding, err error) {
	var merged catalogParts
	merged.Sources = []json.RawMessage{}
	merged.Items = []json.RawMessage{}
	merged.Edges = []json.RawMessage{}
	seenSource := map[string]bool{}
	seenItem := map[string]bool{}
	seenEdge := map[string]bool{}
	cursors := map[string]bool{}
	refs := map[string]bool{}
	offset := 0
	cursor := ""
	total := s.wantedSources()
	if total == 0 {
		return catalog, binding, failure("SESSION_SCOPE", nil)
	}
	for n := 0; n < s.limits.Pages; n++ {
		projection := "page:" + strconv.Itoa(s.query.PageSources)
		if cursor != "" {
			projection += ":" + cursor
		}
		r, e := s.exchange(ctx, request{Version: APIVersion, ID: "knowledge-" + strconv.Itoa(n+1), Op: "knowledge", SourceID: s.query.SourceID, Pin: s.query.Pin, Projection: projection, Budget: &s.query.Budget, DeadlineMS: s.query.DeadlineMS})
		if e != nil {
			return catalog, binding, e
		}
		var p page
		if strictOpaque(r.Result, &p, "catalog") != nil || !required(r.Result, "catalogDigest", "scopeDigest", "queryDigest", "offset", "totalSources", "complete", "externalReferences", "catalog") {
			return catalog, binding, failure("SESSION_WIRE", nil)
		}
		var catPin, queryPin string
		if json.Unmarshal(p.CatalogDigest, &catPin) != nil || !pin(catPin) || json.Unmarshal(p.QueryDigest, &queryPin) != nil || !pin(queryPin) || !jsonEqual(p.ScopeDigest, s.binding.ScopeDigest) {
			return catalog, binding, failure("SESSION_SCOPE", nil)
		}
		if n == 0 {
			s.binding.CatalogDigest = copyRaw(p.CatalogDigest)
			s.binding.QueryDigest = copyRaw(p.QueryDigest)
			s.binding.CatalogSHA256 = catPin
		} else if !jsonEqual(p.CatalogDigest, s.binding.CatalogDigest) || !jsonEqual(p.QueryDigest, s.binding.QueryDigest) {
			return catalog, binding, failure("SESSION_SCOPE", nil)
		}
		if p.Offset != offset || p.TotalSources != total || p.ExternalReferences == nil {
			return catalog, binding, failure("SESSION_CURSOR", nil)
		}
		part, e := parts(p.Catalog)
		if e != nil {
			return catalog, binding, e
		}
		if n == 0 {
			merged.APIVersion = part.APIVersion
			merged.Kind = part.Kind
			merged.ID = part.ID
			merged.Version = part.Version
		}
		if part.APIVersion != knowledge.APIVersion || part.Kind != merged.Kind || part.ID != merged.ID || part.Version != merged.Version {
			return catalog, binding, failure("SESSION_CATALOG_BINDING", nil)
		}
		if len(part.Sources) == 0 || len(part.Sources) > s.query.PageSources || len(part.Sources) > total-offset {
			return catalog, binding, failure("SESSION_BOUNDS", nil)
		}
		pageIDs := map[string]bool{}
		expectedAssets := map[string]AssetDescriptor{}
		for _, obj := range part.Sources {
			var src knowledge.Source
			if json.Unmarshal(obj, &src) != nil {
				return catalog, binding, failure("SESSION_WIRE", nil)
			}
			local, ok := s.source(src.ID)
			if !ok || local.State != "available-static" || seenSource[src.ID] || (s.query.SourceID != "" && s.query.SourceID != src.ID) || src.Pin.Commit != local.Revision || src.Anchor.Commit != local.Revision {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			seenSource[src.ID] = true
			pageIDs[src.ID] = true
			for _, a := range local.Assets {
				key := src.ID + "\x00" + a.Anchor.Path
				if _, exists := expectedAssets[key]; exists {
					return catalog, binding, failure("SESSION_ASSET_AMBIGUITY", nil)
				}
				expectedAssets[key] = a
			}
			merged.Sources = append(merged.Sources, obj)
		}
		foundAssets := map[string]bool{}
		for _, obj := range part.Items {
			var item knowledge.Item
			if json.Unmarshal(obj, &item) != nil {
				return catalog, binding, failure("SESSION_WIRE", nil)
			}
			key := item.SourceID + "\x00" + item.SourcePath
			a, ok := expectedAssets[key]
			if !ok || seenItem[item.ID] || foundAssets[key] || item.Kind != "resource" || item.ContentSHA256 != "sha256:"+a.Anchor.BlobDigest.Hex {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			seenItem[item.ID] = true
			foundAssets[key] = true
			pageIDs[item.ID] = true
			merged.Items = append(merged.Items, obj)
		}
		if len(foundAssets) != len(expectedAssets) {
			return catalog, binding, failure("SESSION_PARTIAL", nil)
		}
		pageEdges := map[string]bool{}
		for _, obj := range part.Edges {
			key := edgeKey(obj)
			if pageEdges[key] || (!pageIDs[objectString(obj, "from")] && !pageIDs[objectString(obj, "to")]) {
				return catalog, binding, failure("SESSION_SCOPE", nil)
			}
			pageEdges[key] = true
			if seenEdge[key] {
				if !containsEdge(merged.Edges, key, obj) {
					return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
				}
			} else {
				seenEdge[key] = true
				merged.Edges = append(merged.Edges, obj)
			}
		}
		for _, ref := range p.ExternalReferences {
			refs[ref] = true
		}
		offset += len(part.Sources)
		if p.Complete {
			if p.NextCursor != "" || offset != total {
				return catalog, binding, failure("SESSION_PARTIAL", nil)
			}
			for ref := range refs {
				if !containsID(merged, ref) {
					return catalog, binding, failure("SESSION_PARTIAL", nil)
				}
			}
			raw, e := json.Marshal(merged)
			if e != nil || len(raw) > knowledge.MaxBytes {
				return catalog, binding, failure("SESSION_BOUNDS", nil)
			}
			if digest(raw) != s.binding.CatalogSHA256 {
				return catalog, binding, failure("SESSION_CATALOG_PIN", nil)
			}
			decoded, e := knowledge.Decode(raw)
			if e != nil {
				return catalog, binding, e
			}
			if e = ctx.Err(); e != nil {
				return catalog, binding, e
			}
			return decoded, copyJSON(s.binding), nil
		}
		if offset == total || !validCursor(p.NextCursor) || cursors[p.NextCursor] {
			return catalog, binding, failure("SESSION_CURSOR", nil)
		}
		cursor = p.NextCursor
		cursors[cursor] = true
	}
	return catalog, binding, failure("SESSION_BOUNDS", nil)
}

// ReadAsset uses a constructor-learned descriptor and commit pin. It cannot read
// a caller-selected path outside that immutable catalog, or execute its content.
func (s *Session) ReadAsset(ctx context.Context, sourceID, assetID string) (content []byte, err error) {
	if s == nil || s.conn == nil || ctx == nil || s.closed.Load() || !s.dynamic {
		return nil, failure("SESSION_LIFETIME", nil)
	}
	if !s.busy.CompareAndSwap(false, true) {
		return nil, failure("SESSION_BUSY", nil)
	}
	defer s.busy.Store(false)
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	src, ok := s.source(sourceID)
	if !ok || src.State != "available-static" || (s.query.SourceID != "" && sourceID != s.query.SourceID) {
		return nil, failure("SESSION_SCOPE", nil)
	}
	var asset AssetDescriptor
	for _, a := range src.Assets {
		if a.ID == assetID {
			asset = a
		}
	}
	if asset.ID == "" {
		return nil, failure("SESSION_SCOPE", nil)
	}
	finish, err := s.deadline(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	s.sequence++
	r, err := s.exchange(ctx, request{Version: APIVersion, ID: "read-" + strconv.Itoa(s.sequence), Op: "read", SourceID: sourceID, AssetID: assetID, Pin: src.Revision, Budget: &s.query.Budget, DeadlineMS: s.query.DeadlineMS})
	if err != nil {
		return nil, err
	}
	var result struct {
		Asset   AssetDescriptor `json:"asset"`
		Content string          `json:"content"`
		Trust   string          `json:"trust"`
	}
	if strict(r.Result, &result) != nil || !required(r.Result, "asset", "content", "trust") || result.Trust != "untrusted-content-not-policy" {
		return nil, failure("SESSION_WIRE", nil)
	}
	actual, _ := json.Marshal(result.Asset)
	expected, _ := json.Marshal(asset)
	data := []byte(result.Content)
	if !jsonEqual(actual, expected) || len(data) != asset.Bytes || len(data) > 8192 || digest(data) != "sha256:"+asset.Anchor.BlobDigest.Hex {
		return nil, failure("SESSION_CATALOG_PIN", nil)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}
