package knowledge

import (
	"encoding/json"
	"strings"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

// Project preserves descriptor metadata in canonical graphdoc attributes. Static
// and declared observations are not signature verification or quality results.
func Project(d Catalog) (graphdoc.Document, error) {
	if err := Validate(d); err != nil {
		return graphdoc.Document{}, err
	}
	g := graphdoc.New()
	g.Layer = "knowledge"
	g.Producer = "tplaiter knowledge/v1"
	known := map[string]bool{}
	for _, s := range d.Sources {
		raw, err := json.Marshal(s)
		if err != nil {
			return graphdoc.Document{}, err
		}
		g.Nodes = append(g.Nodes, graphdoc.Node{ID: s.ID, Kind: "source", Attributes: map[string]string{"descriptor": string(raw), "evidenceState": "declared", "catalogId": d.ID, "catalogVersion": d.Version}, Provenance: []graphdoc.Provenance{{Source: s.Pin.Origin, Evidence: s.Anchor.StatementCAS, Declared: true}}})
		known[s.ID] = true
	}
	for _, it := range d.Items {
		raw, err := json.Marshal(it)
		if err != nil {
			return graphdoc.Document{}, err
		}
		g.Nodes = append(g.Nodes, graphdoc.Node{ID: it.ID, Kind: it.Kind, Path: it.SourcePath, Name: it.ID, Attributes: map[string]string{"descriptor": string(raw), "evidenceState": "declared", "catalogId": d.ID, "catalogVersion": d.Version}, Provenance: []graphdoc.Provenance{{Source: it.SourceID, Evidence: it.ContentSHA256, Declared: true}}})
		known[it.ID] = true
	}
	for _, e := range append(declaredEdges(d), d.Edges...) {
		for _, id := range []string{e.From, e.To} {
			if !known[id] {
				known[id] = true
				g.Nodes = append(g.Nodes, graphdoc.Node{ID: id, Kind: strings.Split(id, ":")[1], Attributes: map[string]string{"evidenceState": "unresolved"}})
			}
		}
		g.Edges = append(g.Edges, graphdoc.Edge{From: e.From, To: e.To, Kind: e.Layer + ":" + e.Relation, Attributes: map[string]string{"layer": e.Layer, "evidenceState": e.State}, Provenance: []graphdoc.Provenance{{Declared: true}}})
		if e.State == "unresolved" {
			g.Status = "partial"
			g.Diagnostics = append(g.Diagnostics, graphdoc.Diagnostic{Code: Unresolved, Severity: "warning", Message: "Unresolved declared relation", Path: e.From})
		}
	}
	if err := g.Canonicalize(); err != nil {
		return graphdoc.Document{}, err
	}
	return g, nil
}

// Static is a provider-supplied observation label. Only ObserveSource emits
// Detected provenance for bytes the core actually verified.
func declaredEdges(d Catalog) []Edge {
	edges := make([]Edge, 0, len(d.Items))
	aliases := map[string]string{}
	for _, s := range d.Sources {
		aliases[s.Pin.Alias] = s.ID
	}
	for _, s := range d.Sources {
		for _, dep := range s.Pin.Dependencies {
			edges = append(edges, Edge{From: aliases[dep], To: s.ID, Layer: "source", Relation: "depends-on", State: "declared"})
		}
	}
	for _, it := range d.Items {
		edges = append(edges, Edge{From: it.SourceID, To: it.ID, Layer: "source", Relation: "anchors", State: "declared"})
		for _, ref := range it.Inputs.ContextFloor {
			edges = append(edges, Edge{From: ref, To: it.ID, Layer: "workflow", Relation: "context-floor", State: "declared"})
		}
		for _, ref := range it.Requires {
			edges = append(edges, Edge{From: ref, To: it.ID, Layer: "workflow", Relation: "requires", State: "declared"})
		}
		for _, ref := range it.Produces {
			edges = append(edges, Edge{From: it.ID, To: ref, Layer: "workflow", Relation: "produces", State: "declared"})
		}
	}
	return edges
}
