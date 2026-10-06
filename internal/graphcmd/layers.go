package graphcmd

import (
	"fmt"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func sourceRecords(g deps.SourceGraph, pins []deps.PinnedSource) ([]resultdto.GraphRecord, error) {
	if e := deps.ValidateSourceGraph(&g); e != nil {
		return nil, e
	}
	out := []resultdto.GraphRecord{}
	for _, n := range g.Nodes {
		linked := []deps.PinnedSource{}
		for _, prov := range n.Provenance {
			for _, pin := range pins {
				if pin.Alias == prov.Alias {
					linked = append(linked, pin)
				}
			}
		}
		if len(linked) != len(n.Provenance) {
			return nil, fail("GRAPH_SOURCE_ADMISSION")
		}
		node := n
		out = append(out, resultdto.GraphRecord{Kind: "source", Identity: n.Key, Source: &node, Pins: linked})
	}
	for _, e := range g.Edges {
		edge := e
		out = append(out, resultdto.GraphRecord{Kind: "source-edge", SourceEdge: &edge})
	}
	return out, nil
}
func exportRecords(g exports.ExportGraph) ([]resultdto.GraphRecord, error) {
	digest, e := exports.ExportGraphDigest(g.Selected, g.Edges)
	if e != nil || digest != g.Digest {
		return nil, fail("GRAPH_SELECTOR_INVALID")
	}
	out := []resultdto.GraphRecord{}
	seen := map[string]bool{}
	for _, s := range g.Selected {
		id, e := exports.SelectedExportIdentity(s)
		if e != nil || seen[id] {
			return nil, fmt.Errorf("graph: complete export identity collision")
		}
		seen[id] = true
		v := s
		out = append(out, resultdto.GraphRecord{Kind: "export", Identity: id, Export: &v})
	}
	for _, edge := range g.Edges {
		v := edge
		out = append(out, resultdto.GraphRecord{Kind: "export-edge", ExportEdge: &v})
	}
	return out, nil
}
func astRecords(g graphdoc.Document) ([]resultdto.GraphRecord, error) {
	if e := graphdoc.Verify(g); e != nil {
		return nil, e
	}
	out := []resultdto.GraphRecord{}
	for _, n := range g.Nodes {
		v := n
		out = append(out, resultdto.GraphRecord{Kind: "ast-node", Identity: n.ID, Node: &v})
	}
	for _, e := range g.Edges {
		v := e
		out = append(out, resultdto.GraphRecord{Kind: "ast-edge", Edge: &v})
	}
	for _, d := range g.Diagnostics {
		v := d
		out = append(out, resultdto.GraphRecord{Kind: "ast-diagnostic", Diagnostic: &v})
	}
	return out, nil
}
