package knowledge

import (
	"encoding/json"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

// ProjectExportCatalog binds selected knowledge exports to the existing exact
// source graph key and export entry. All results remain declared metadata.
func ProjectExportCatalog(d Catalog, sourceID string, raw []byte) (graphdoc.Document, error) {
	g, err := Project(d)
	if err != nil {
		return graphdoc.Document{}, err
	}
	c, err := exports.ParseCatalog(raw)
	if err != nil {
		return graphdoc.Document{}, fmt.Errorf("knowledge: export catalog: %w", err)
	}
	pins := make([]deps.PinnedSource, 0, len(d.Sources))
	var selected Source
	for _, s := range d.Sources {
		pins = append(pins, s.Pin)
		if s.ID == sourceID {
			selected = s
		}
	}
	sg, err := deps.BuildSourceGraph(pins)
	if err != nil {
		return graphdoc.Document{}, fmt.Errorf("knowledge: source graph: %w", err)
	}
	key := ""
	for _, n := range sg.Nodes {
		for _, p := range n.Provenance {
			if p.Alias == selected.Pin.Alias {
				key = n.Key
			}
		}
	}
	if key == "" || c.Source != key || c.Provider != selected.Pin.ProviderID || c.ContractDigest != selected.Pin.ContractDigest {
		return graphdoc.Document{}, fail(SourceMismatch, "export catalog")
	}
	matched := 0
	for _, it := range d.Items {
		if it.SourceID != sourceID || it.Export == nil {
			continue
		}
		want, err := canonicaljson.Canonical(it.Export)
		if err != nil {
			return graphdoc.Document{}, err
		}
		found := false
		for _, entry := range c.Exports {
			got, err := canonicaljson.Canonical(entry)
			if err != nil {
				return graphdoc.Document{}, err
			}
			if string(got) == string(want) {
				found = true
			}
		}
		if !found {
			return graphdoc.Document{}, fail(SourceMismatch, it.ID+".export")
		}
		matched++
		for i := range g.Nodes {
			if g.Nodes[i].ID == it.ID {
				g.Nodes[i].Attributes["exportCatalogSource"] = c.Source
				g.Nodes[i].Attributes["exportProvider"] = c.Provider
			}
		}
	}
	if matched == 0 {
		return graphdoc.Document{}, fail(SourceMismatch, "no selected exports")
	}
	if err := g.Canonicalize(); err != nil {
		return graphdoc.Document{}, err
	}
	return g, nil
}

// ProjectBlockExport reads the public managed-block contract without loading
// bodies or running its formatter. Provider/local ID/body identify a block;
// matching by an unqualified local ID alone is deliberately insufficient.
func ProjectBlockExport(d Catalog, sourceID string, raw []byte) (graphdoc.Document, error) {
	g, err := Project(d)
	if err != nil {
		return graphdoc.Document{}, err
	}
	b, err := blockexport.Parse(raw)
	if err != nil {
		return graphdoc.Document{}, fmt.Errorf("knowledge: block export: %w", err)
	}
	selected := Source{}
	for _, s := range d.Sources {
		if s.ID == sourceID {
			selected = s
		}
	}
	if selected.ID == "" {
		return graphdoc.Document{}, fail(SourceMismatch, "block source")
	}
	matched := map[string]bool{}
	for _, target := range b.Targets {
		for _, block := range target.Blocks {
			id := ""
			for _, it := range d.Items {
				if it.SourceID == sourceID && it.Kind == "block" && it.Export != nil && it.Export.Domain == "block" && it.Export.ID == block.ID && it.SourcePath == block.Body && it.Version == b.Metadata.Version && block.Provider == selected.Pin.ProviderID {
					if id != "" || matched[it.ID] {
						return graphdoc.Document{}, fail(AmbiguousID, "block mapping")
					}
					id = it.ID
				}
			}
			if id == "" {
				return graphdoc.Document{}, fail(SourceMismatch, "block mapping")
			}
			matched[id] = true
			metadata := struct {
				Metadata      blockexport.Metadata      `json:"metadata"`
				Compatibility blockexport.Compatibility `json:"compatibility"`
				MergeStrategy string                    `json:"mergeStrategy"`
				Formatter     blockexport.Formatter     `json:"formatter"`
				Target        string                    `json:"target"`
				Block         blockexport.Block         `json:"block"`
			}{b.Metadata, b.Compatibility, b.MergeStrategy, b.Formatter, target.Path, block}
			encoded, err := json.Marshal(metadata)
			if err != nil {
				return graphdoc.Document{}, err
			}
			if len(encoded) > graphdoc.MaxString {
				return graphdoc.Document{}, fail(Invalid, "block metadata limit")
			}
			for i := range g.Nodes {
				if g.Nodes[i].ID == id {
					g.Nodes[i].Attributes["blockExport"] = string(encoded)
				}
			}
		}
	}
	if err := g.Canonicalize(); err != nil {
		return graphdoc.Document{}, err
	}
	return g, nil
}
