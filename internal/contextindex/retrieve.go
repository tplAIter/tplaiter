package contextindex

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const APIVersion = "tplaiter.dev/context-index-result/v1"

type Request struct {
	Query           Query
	Limit           int // primary matches only; mandatory floor is additional and explicit
	MaxRecords      int // total records plus pinned source records
	MaxBytes        int // exact serialized JSON bytes, not tokens
	Required        []string
	IncludeExcerpts bool
	MaxExcerptBytes int
}

// Binding carries only existing concrete authority; ID is matched to the full
// descriptor subject and evidence by knowledge.ObserveSource on every retrieval.
type Binding struct {
	SourceID   string
	Runtime    *trustverify.Runtime
	Resolution *trustverify.VerifiedResolution
}

type Reference struct {
	ID    string `json:"id"`
	State string `json:"state"`
}
type SourceEvidence struct {
	SourceID     string `json:"sourceId"`
	StatementCAS string `json:"statementCAS"`
	Scope        string `json:"scope"`
}

type Packet struct {
	APIVersion         string                      `json:"apiVersion"`
	GraphDigest        string                      `json:"graphDigest"`
	Records            []Record                    `json:"records"`
	Sources            []knowledge.Source          `json:"sources"`
	Relations          []graphdoc.Edge             `json:"relations"`
	ExternalReferences []Reference                 `json:"externalReferences"`
	RequiredFloor      []string                    `json:"requiredFloor"`
	SourceEvidence     []SourceEvidence            `json:"sourceEvidence"`
	Excerpts           []contextpack.SourceExcerpt `json:"excerpts"`
	TotalMatches       int                         `json:"totalMatches"`
	OmittedMatches     int                         `json:"omittedMatches"`
	Bytes              int                         `json:"bytes"`
}

// Retrieve retains the complete required/dependency floor and every incident
// relation, including references outside the selection. If mandatory context
// exceeds count/byte bounds it refuses; it never silently prunes that floor.
// Metadata-only calls perform no authority or source reads.
func (i *Index) Retrieve(ctx context.Context, req Request, bindings []Binding) (Packet, error) {
	if ctx == nil {
		return Packet{}, diagnostic(Invalid, "context")
	}
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	matches, err := i.matches(req.Query)
	if err != nil {
		return Packet{}, err
	}
	limit, maxRecords, maxBytes := req.Limit, req.MaxRecords, req.MaxBytes
	if limit == 0 {
		limit = 8
	}
	if maxRecords == 0 {
		maxRecords = 64
	}
	if maxBytes == 0 {
		maxBytes = contextpack.DefaultLimit
	}
	if limit < 1 || limit > 64 || maxRecords < 1 || maxRecords > 256 || maxBytes < 1 || maxBytes > contextpack.HardLimit || len(req.Required) > 32 {
		return Packet{}, diagnostic(Invalid, "limits")
	}
	p := Packet{APIVersion: APIVersion, GraphDigest: i.graph.Digest, Records: []Record{}, Sources: []knowledge.Source{}, Relations: []graphdoc.Edge{}, ExternalReferences: []Reference{}, RequiredFloor: []string{}, SourceEvidence: []SourceEvidence{}, Excerpts: []contextpack.SourceExcerpt{}, TotalMatches: len(matches)}
	if len(matches) > limit {
		matches = matches[:limit]
	}
	p.OmittedMatches = p.TotalMatches - len(matches)
	selected := map[string]bool{}
	add := func(id string) error {
		if _, ok := i.records[id]; ok {
			selected[id] = true
			return nil
		}
		if _, ok := i.sources[id]; ok {
			selected[id] = true
			return nil
		}
		return diagnostic(Missing, id)
	}
	for _, r := range matches {
		selected[r.ID] = true
		if err := add(r.ItemID); err != nil {
			return Packet{}, err
		}
	}
	for _, id := range req.Required {
		if err := add(id); err != nil {
			return Packet{}, err
		}
	}
	// Graph predecessor closure follows only actual dependency relations. Semantic
	// and package edges remain explicit references, not invented prerequisites.
	for changed := true; changed; {
		changed = false
		for _, edge := range i.graph.Edges {
			if selected[edge.To] && oneOf(edge.Kind, "source:anchors", "source:depends-on", "workflow:requires", "workflow:context-floor", "workflow:produces", "export:depends-on") && !selected[edge.From] {
				if err := add(edge.From); err != nil {
					return Packet{}, err
				}
				changed = true
			}
		}
		for id := range selected {
			if r, ok := i.records[id]; ok && !selected[r.ItemID] {
				if err := add(r.ItemID); err != nil {
					return Packet{}, err
				}
				changed = true
			}
		}
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p.RequiredFloor = append(p.RequiredFloor, id)
		if r, ok := i.records[id]; ok {
			p.Records = append(p.Records, r)
		} else {
			p.Sources = append(p.Sources, i.sources[id])
		}
	}
	if len(p.Records)+len(p.Sources) > maxRecords {
		return Packet{}, diagnostic(Budget, "required floor count")
	}
	known := map[string]string{}
	for _, n := range i.graph.Nodes {
		state := n.Attributes["evidenceState"]
		if state == "" {
			state = "declared"
		}
		known[n.ID] = state
	}
	external := map[string]string{}
	for _, edge := range i.graph.Edges {
		if selected[edge.From] || selected[edge.To] {
			p.Relations = append(p.Relations, edge)
			for _, id := range []string{edge.From, edge.To} {
				if !selected[id] {
					external[id] = known[id]
				}
			}
		}
	}
	refs := make([]string, 0, len(external))
	for id := range external {
		refs = append(refs, id)
	}
	sort.Strings(refs)
	for _, id := range refs {
		p.ExternalReferences = append(p.ExternalReferences, Reference{ID: id, State: external[id]})
	}
	if !fit(&p, maxBytes) {
		return Packet{}, diagnostic(Budget, "required floor bytes")
	}
	if req.IncludeExcerpts {
		if err := i.excerpts(ctx, &p, req, bindings); err != nil {
			return Packet{}, err
		}
		if !fit(&p, maxBytes) {
			return Packet{}, diagnostic(Budget, "excerpts bytes")
		}
	}
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	return clonePacket(p)
}

func fit(p *Packet, maxBytes int) bool {
	for range 32 {
		raw, err := json.Marshal(p)
		if err != nil {
			return false
		}
		if len(raw) == p.Bytes {
			return p.Bytes <= maxBytes
		}
		p.Bytes = len(raw)
	}
	return false
}
