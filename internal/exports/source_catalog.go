package exports

import (
	"encoding/json"
	"errors"

	"github.com/tplAIter/tplaiter/internal/deps"
)

// CatalogData is inert immutable source data collected by an admitted caller.
// It has no readers, commands or trust flags. Authentication belongs to that
// caller; content validation here does not grant publisher or host authority.
type CatalogData struct {
	Entries  []byte
	Tool     []byte
	Payloads []SourcePayload
	Blobs    []MaterialBlob
}

type SourcePayload struct {
	ExportID string
	Raw      []byte
}

// SourceCatalogInput supplies the complete pinned graph and one declared alias.
// The graph is reconstructed by the existing source engine, never caller-keyed.
type SourceCatalogInput struct {
	Pins  []deps.PinnedSource
	Alias string
	Data  CatalogData
}

type SourceCatalog struct {
	Catalog  Catalog
	Sources  *deps.SourceGraph
	Payloads []SourcePayload
	Blobs    []MaterialBlob
}

// BuildSourceCatalog derives an existing closed Catalog from strict authored
// entries after source capture. It never resolves refs or executes provider code.
// ResolveSelection(s) validates closure after all source catalogs are built.
func BuildSourceCatalog(in SourceCatalogInput) (SourceCatalog, error) {
	bad := func() (SourceCatalog, error) { return SourceCatalog{}, errors.New("EXPORT_DATA: invalid source data") }
	graph, err := deps.BuildSourceGraph(in.Pins)
	if err != nil {
		return SourceCatalog{}, err
	}
	var pin *deps.PinnedSource
	for i := range in.Pins {
		if in.Pins[i].Alias == in.Alias {
			pin = &in.Pins[i]
		}
	}
	if pin == nil || len(in.Data.Entries) == 0 || len(in.Data.Entries) > maxCatalogWireBytes || len(in.Data.Tool) == 0 || len(in.Data.Tool) > maxCatalogWireBytes || in.Data.Payloads == nil || in.Data.Blobs == nil || len(in.Data.Payloads) > 4096 || len(in.Data.Blobs) > 4096 {
		return bad()
	}
	key := ""
	for _, node := range graph.Nodes {
		for _, provenance := range node.Provenance {
			if provenance.Alias == in.Alias {
				key = node.Key
			}
		}
	}
	// Wrapping raw authored entries preserves duplicate/unknown wire-field and
	// scalar lexical validation in ParseCatalog rather than normalizing first.
	wire, err := json.Marshal(struct {
		APIVersion string          `json:"apiVersion"`
		Provider   string          `json:"provider"`
		Source     string          `json:"source"`
		Contract   string          `json:"contractDigest"`
		Exports    json.RawMessage `json:"exports"`
	}{CatalogAPIVersion, pin.ProviderID, key, pin.ContractDigest, in.Data.Entries})
	if err != nil {
		return bad()
	}
	catalog, err := ParseCatalog(wire)
	if err != nil {
		return SourceCatalog{}, err
	}
	// The authored array must use exact field names at every record level;
	// encoding/json's case-insensitive struct matching is not an extension.
	var records []json.RawMessage
	if err := json.Unmarshal(in.Data.Entries, &records); err != nil {
		return bad()
	}
	for _, raw := range records {
		var entry ExportEntry
		if err := decodeClosed(raw, []string{"id", "domain", "name", "version", "contentDigest", "parameters", "toolDigest", "requires"}, &entry); err != nil {
			return SourceCatalog{}, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return bad()
		}
		for _, collection := range []struct {
			name   string
			fields []string
		}{
			{"parameters", []string{"name", "value"}},
			{"requires", []string{"selector", "contractDigest", "compatibleRange"}},
		} {
			var elements []json.RawMessage
			if err := json.Unmarshal(fields[collection.name], &elements); err != nil {
				return bad()
			}
			for _, element := range elements {
				var record map[string]json.RawMessage
				if err := decodeClosed(element, collection.fields, &record); err != nil {
					return SourceCatalog{}, err
				}
			}
		}
	}
	payloads := map[string][]byte{}
	parsedPayloads := map[string]ExportPayload{}
	var total uint64
	for _, p := range in.Data.Payloads {
		if !exportTokenRE.MatchString(p.ExportID) || len(p.Raw) == 0 || len(p.Raw) > maxCatalogWireBytes {
			return bad()
		}
		// Parse every raw record before any duplicate decision.
		parsed, err := ParseExportPayload(p.Raw)
		if err != nil {
			return SourceCatalog{}, err
		}
		if parsed.ExportID != p.ExportID || len(parsed.Files) == 0 || len(parsed.Slots) != 0 || len(parsed.Blocks) != 0 || payloads[p.ExportID] != nil {
			return bad()
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(p.Raw, &fields); err != nil {
			return bad()
		}
		var files []json.RawMessage
		if err := json.Unmarshal(fields["files"], &files); err != nil {
			return bad()
		}
		for _, raw := range files {
			var file PayloadFile
			if err := decodeClosed(raw, []string{"sourcePath", "targetPath", "mode", "contentSHA256"}, &file); err != nil {
				return SourceCatalog{}, err
			}
		}
		total += uint64(len(p.Raw))
		payloads[p.ExportID] = p.Raw
		parsedPayloads[p.ExportID] = parsed
	}
	blobs := map[string]MaterialBlob{}
	for _, b := range in.Data.Blobs {
		if payloadPath(b.Path) != nil || (b.Mode != "100644" && b.Mode != "100755") || len(b.Content) > 16<<20 {
			return bad()
		}
		if _, exists := blobs[b.Path]; exists {
			return bad()
		}
		total += uint64(len(b.Content))
		blobs[b.Path] = b
	}
	if total > 64<<20 || len(payloads) != len(catalog.Exports) {
		return bad()
	}
	used := map[string]bool{}
	out := SourceCatalog{Catalog: catalog, Sources: graph, Payloads: []SourcePayload{}, Blobs: []MaterialBlob{}}
	for _, entry := range catalog.Exports {
		raw, ok := payloads[entry.ID]
		if !ok || digestBytes(raw) != entry.ContentDigest || digestBytes(in.Data.Tool) != entry.ToolDigest {
			return bad()
		}
		payload := parsedPayloads[entry.ID]
		for _, f := range payload.Files {
			b, ok := blobs[f.SourcePath]
			if !ok || b.Mode != f.Mode || digestBytes(b.Content) != f.ContentSHA256 {
				return bad()
			}
			used[b.Path] = true
		}
		out.Payloads = append(out.Payloads, SourcePayload{ExportID: entry.ID, Raw: append([]byte(nil), raw...)})
	}
	if len(used) != len(blobs) {
		return bad()
	}
	for _, b := range in.Data.Blobs {
		out.Blobs = append(out.Blobs, MaterialBlob{Path: b.Path, Mode: b.Mode, Content: append([]byte(nil), b.Content...)})
	}
	return out, nil
}
