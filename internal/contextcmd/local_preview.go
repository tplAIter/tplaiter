package contextcmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/providerclient"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// LocalPreviewRequest selects only installed IDs and bounds; never endpoints,
// provider code, source authentication or credentials.
type LocalPreviewRequest struct {
	IncludeCatalogWire    bool     `json:"includeCatalogWire,omitempty"`
	RegistrationID        string   `json:"registrationID"`
	SourceID              string   `json:"sourceID,omitempty"`
	AssetID               string   `json:"assetID,omitempty"`
	Required              []string `json:"required,omitempty"`
	Text                  string   `json:"text,omitempty"`
	Limit                 int      `json:"limit,omitempty"`
	MaxRecords            int      `json:"maxRecords,omitempty"`
	MaxBytes              int      `json:"maxBytes,omitempty"`
	ExpectedCatalogSHA256 string   `json:"expectedCatalogSHA256,omitempty"`
}

func NormalizeLocalPreview(action string, r *LocalPreviewRequest) error {
	if r == nil || r.RegistrationID == "" || !utf8.ValidString(r.RegistrationID) || len(r.RegistrationID) > 64 || strings.ContainsAny(r.RegistrationID, "\x00\t\r\n /\\") || len(r.Required) > 32 || len(r.Text) > 256 {
		return fail(Invalid)
	}
	if action != "preview-catalog" && action != "preview-resource" {
		return fail(Invalid)
	}
	if action == "preview-catalog" && (r.SourceID != "" || r.AssetID != "") {
		return fail(Invalid)
	}
	if action == "preview-resource" && (r.SourceID == "" || r.AssetID == "" || r.Text != "") {
		return fail(Invalid)
	}
	if len(r.SourceID) > 256 || len(r.AssetID) > 256 {
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
	if r.Limit < 1 || r.Limit > 16 || r.MaxRecords < 1 || r.MaxRecords > 256 || r.MaxBytes < 1 || r.MaxBytes > 32768 {
		return fail(Invalid)
	}
	if r.ExpectedCatalogSHA256 != "" {
		pin := r.ExpectedCatalogSHA256
		if len(pin) != 71 || !strings.HasPrefix(pin, "sha256:") {
			return fail(Invalid)
		}
		for _, c := range pin[7:] {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return fail(Invalid)
			}
		}
	}
	return nil
}

func RunLocalPreview(ctx context.Context, r *trustload.Runtime, action string, req LocalPreviewRequest) (resultdto.ContextData, error) {
	var empty resultdto.ContextData
	if ctx == nil || r == nil {
		return empty, fail(Invalid)
	}
	if err := NormalizeLocalPreview(action, &req); err != nil {
		return empty, err
	}
	host, err := r.OpenLocalProvider(ctx, req.RegistrationID)
	if err != nil {
		return empty, err
	}
	defer host.Close()
	l := host.Limits()
	bounded, cancel := context.WithDeadline(ctx, host.Deadline())
	defer cancel()
	session, err := providerclient.Open(bounded, host, providerclient.Query{PageSources: 1, DeadlineMS: l.DeadlineMs, Budget: providerclient.Budget{SourceBytes: l.SourceBytes}}, providerclient.Limits{FrameBytes: l.FrameBytes, TotalBytes: l.TotalBytes, Pages: l.Pages, Timeout: time.Duration(l.DeadlineMs) * time.Millisecond})
	if err != nil {
		return empty, err
	}
	defer session.Close()
	catalog, err := session.ReadCatalogReceipt(bounded)
	if err != nil {
		return empty, err
	}
	pin := catalog.Binding()
	if req.ExpectedCatalogSHA256 != "" && req.ExpectedCatalogSHA256 != pin.CatalogSHA256 {
		return empty, fail(Stale)
	}
	decoded, err := knowledge.Decode(catalog.Bytes())
	if err != nil {
		return empty, err
	}
	index, err := contextindex.New(catalog.Bytes(), nil)
	if err != nil {
		return empty, err
	}
	query := contextindex.Query{Text: req.Text}
	if action == "preview-resource" {
		item, _, e := previewAsset(catalog, decoded, req.SourceID, req.AssetID)
		if e != nil {
			return empty, e
		}
		query = contextindex.Query{ID: item.ID, One: true}
	}
	metadata, err := index.Retrieve(bounded, contextindex.Request{Query: query, Required: req.Required, Limit: req.Limit, MaxRecords: req.MaxRecords, MaxBytes: req.MaxBytes, IncludeExcerpts: false}, nil)
	if err != nil {
		return empty, err
	}
	selected := host.Selection()
	out := resultdto.ContextData{Action: action, Snapshot: pin.CatalogSHA256, CatalogOrigin: "installed-local-observed", Entries: []resultdto.ContextEntry{}, Total: metadata.TotalMatches, WindowState: "unknown", WindowReason: WindowUnknown, RetrievalState: "local-untrusted-preview"}
	preview := &resultdto.LocalPreviewData{APIVersion: "tplaiter.dev/context-local-preview/v1", Kind: "LocalContextPreview", Qualification: trustload.LocalObserved, SourceAuthentication: "none", PublisherAuthentication: "none", OrganizationAdmission: "none", Selection: resultdto.LocalPreviewSelection(selected), Observation: resultdto.LocalPreviewObservation{CatalogSHA256: pin.CatalogSHA256, CatalogByteLength: len(catalog.Bytes()), HandshakeResultSHA256: pin.HandshakeResultSHA256, SchemaSHA256: pin.SchemaSHA256, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, Metadata: metadata, Resources: []resultdto.LocalPreviewResource{}}
	if req.IncludeCatalogWire {
		preview.CatalogWire = &resultdto.LocalPreviewBytes{Encoding: "base64", Data: base64.StdEncoding.EncodeToString(catalog.Bytes()), SHA256: pin.CatalogSHA256, ByteLength: len(catalog.Bytes())}
	}
	selectedItems := map[string]bool{}
	for _, record := range metadata.Records {
		selectedItems[record.ItemID] = true
	}
	preview.Assets = []resultdto.LocalPreviewAsset{}
	for _, source := range catalog.Descriptors() {
		for _, asset := range source.Assets {
			item, _, e := previewAsset(catalog, decoded, source.ID, asset.ID)
			if e != nil {
				return empty, e
			}
			if !selectedItems[item.ID] {
				continue
			}
			preview.Assets = append(preview.Assets, resultdto.LocalPreviewAsset{SourceID: source.ID, AssetID: asset.ID, ItemID: item.ID, Path: asset.Anchor.Path, Revision: asset.Anchor.Revision, ContentSHA256: "sha256:" + asset.Anchor.BlobDigest.Hex, DescriptorDigest: asset.DescriptorDigest.Algorithm + ":" + asset.DescriptorDigest.Domain + ":" + asset.DescriptorDigest.Hex, ByteLength: asset.Bytes, ResourceURI: PreviewResourceURI(selected.ProjectContext, selected.RegistrationID, pin.CatalogSHA256, source.ID, asset.ID)})
		}
	}
	if action == "preview-resource" {
		for _, id := range metadata.RequiredFloor {
			for _, item := range decoded.Items {
				if item.ID != id || item.Kind != "resource" {
					continue
				}
				var asset providerclient.AssetDescriptor
				matches := 0
				for _, source := range catalog.Descriptors() {
					if source.ID != item.SourceID {
						continue
					}
					for _, a := range source.Assets {
						if a.Anchor.Path == item.SourcePath {
							asset = a
							matches++
						}
					}
				}
				if matches != 1 {
					return empty, fail(SourceUnavailable)
				}
				body, e := session.ReadAssetReceipt(bounded, catalog, item.SourceID, asset.ID)
				if e != nil {
					return empty, e
				}
				bytes := body.Bytes()
				preview.Resources = append(preview.Resources, resultdto.LocalPreviewResource{SourceID: item.SourceID, AssetID: asset.ID, ItemID: item.ID, Path: item.SourcePath, DeclaredMode: item.Mode, ContentSHA256: item.ContentSHA256, DescriptorDigest: asset.DescriptorDigest.Algorithm + ":" + asset.DescriptorDigest.Domain + ":" + asset.DescriptorDigest.Hex, Encoding: "base64", Data: base64.StdEncoding.EncodeToString(bytes), ByteLength: len(bytes), ResourceURI: PreviewResourceURI(selected.ProjectContext, selected.RegistrationID, pin.CatalogSHA256, item.SourceID, asset.ID)})
			}
		}
	}
	if err = host.Recheck(bounded); err != nil {
		return empty, err
	}
	if err = bounded.Err(); err != nil {
		return empty, err
	}
	out.LocalPreview = preview
	for range 32 {
		raw, e := json.Marshal(preview)
		if e != nil {
			return empty, e
		}
		if len(raw) == preview.Bytes {
			break
		}
		preview.Bytes = len(raw)
	}
	if !fit(&out, req.MaxBytes) {
		return empty, fail(Budget)
	}
	return out, nil
}

func previewAsset(receipt *providerclient.CatalogReceipt, catalog knowledge.Catalog, sourceID, assetID string) (knowledge.Item, providerclient.AssetDescriptor, error) {
	var item knowledge.Item
	var asset providerclient.AssetDescriptor
	matches := 0
	for _, source := range receipt.Descriptors() {
		if source.ID != sourceID {
			continue
		}
		for _, a := range source.Assets {
			if a.ID == assetID {
				asset = a
			}
		}
	}
	if asset.ID == "" {
		return item, asset, fail(Missing)
	}
	for _, candidate := range catalog.Items {
		if candidate.SourceID == sourceID && candidate.SourcePath == asset.Anchor.Path && candidate.Kind == "resource" {
			item = candidate
			matches++
		}
	}
	if matches != 1 {
		return item, asset, fail(SourceUnavailable)
	}
	return item, asset, nil
}

func PreviewResourceURI(project, registration, pin, source, asset string) string {
	xs := []string{project, registration, pin, source, asset}
	for i := range xs {
		xs[i] = strings.ReplaceAll(url.PathEscape(xs[i]), ":", "%3A")
	}
	return "tplaiter://context-preview/" + strings.Join(xs, "/")
}

func ParsePreviewResourceURI(raw string) (project string, req LocalPreviewRequest, err error) {
	if len(raw) > 2048 {
		return "", req, fail(Invalid)
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "tplaiter" || u.Host != "context-preview" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", req, fail(Invalid)
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(parts) != 5 {
		return "", req, fail(Invalid)
	}
	for i := range parts {
		parts[i], e = url.PathUnescape(parts[i])
		if e != nil || parts[i] == "" || len(parts[i]) > 256 || strings.ContainsAny(parts[i], "/\\\x00\r\n") {
			return "", req, fail(Invalid)
		}
	}
	project = parts[0]
	req = LocalPreviewRequest{RegistrationID: parts[1], ExpectedCatalogSHA256: parts[2], SourceID: parts[3], AssetID: parts[4], MaxBytes: 32768}
	if PreviewResourceURI(project, req.RegistrationID, req.ExpectedCatalogSHA256, req.SourceID, req.AssetID) != raw {
		return "", req, fail(Invalid)
	}
	return project, req, NormalizeLocalPreview("preview-resource", &req)
}
