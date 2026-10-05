// Package contextindex indexes declared knowledge metadata and retrieves bounded
// task context. Excerpts require fresh opaque source authentication, not labels.
package contextindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

const (
	Invalid   = "CONTEXT_INDEX_INVALID"
	Missing   = "CONTEXT_INDEX_MISSING"
	Ambiguous = "CONTEXT_INDEX_AMBIGUOUS"
	Budget    = "CONTEXT_INDEX_BUDGET"
	Stale     = "CONTEXT_INDEX_STALE"
)

type Error struct{ Code, ID string }

func (e *Error) Error() string         { return e.Code + ": " + e.ID }
func diagnostic(code, id string) error { return &Error{Code: code, ID: id} }

// Symbol is provider-supplied metadata anchored to a pinned knowledge item.
// Static is a declared static report, not proof that core parsed or ran code.
type Symbol struct {
	ID     string `json:"id"`
	ItemID string `json:"itemId"`
	Name   string `json:"name"`
	Line   int    `json:"line"`
	State  string `json:"state"`
}

type Record struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	ItemID     string          `json:"itemId"`
	SourceID   string          `json:"sourceId"`
	Path       string          `json:"path"`
	Name       string          `json:"name"`
	Line       int             `json:"line"`
	State      string          `json:"state"`
	Descriptor *knowledge.Item `json:"descriptor,omitempty"`
}

// Index owns all input bytes and contains no caller-supplied authority callback.
type Index struct {
	raw     []byte
	graph   graphdoc.Document
	records map[string]Record
	sources map[string]knowledge.Source
	items   map[string]knowledge.Item
}

var symbolIDRE = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}:symbol:[a-z][a-z0-9._-]{0,63}$`)

func New(raw []byte, symbols []Symbol) (*Index, error) {
	owned := append([]byte(nil), raw...)
	d, err := knowledge.Decode(owned)
	if err != nil {
		return nil, err
	}
	g, err := knowledge.Project(d)
	if err != nil {
		return nil, err
	}
	if len(symbols) > 512 {
		return nil, diagnostic(Budget, "symbols")
	}
	idx := &Index{raw: owned, graph: g, records: map[string]Record{}, sources: map[string]knowledge.Source{}, items: map[string]knowledge.Item{}}
	for _, s := range d.Sources {
		idx.sources[s.ID] = s
	}
	anchors := map[string]string{}
	for _, item := range d.Items {
		it := item
		idx.items[it.ID] = it
		idx.records[it.ID] = Record{ID: it.ID, Kind: it.Kind, ItemID: it.ID, SourceID: it.SourceID, Path: it.SourcePath, Name: it.ID, Line: 1, State: "declared", Descriptor: &it}
		key := it.SourceID + "\x00" + it.SourcePath
		if prior, ok := anchors[key]; ok {
			p := idx.items[prior]
			if p.ContentSHA256 != it.ContentSHA256 || p.Mode != it.Mode {
				return nil, diagnostic(Stale, it.ID)
			}
			// One path record for an identical anchor; choose stable minimum item ID.
			if it.ID < prior {
				anchors[key] = it.ID
			}
		} else {
			anchors[key] = it.ID
		}
	}
	for key, itemID := range anchors {
		it := idx.items[itemID]
		h := sha256.Sum256([]byte(key))
		namespace := strings.Split(it.SourceID, ":")[0]
		id := namespace + ":path:p-" + hex.EncodeToString(h[:])
		idx.records[id] = Record{ID: id, Kind: "path", ItemID: it.ID, SourceID: it.SourceID, Path: it.SourcePath, Name: it.SourcePath, Line: 1, State: "declared"}
	}
	for _, s := range symbols {
		it, ok := idx.items[s.ItemID]
		if !ok {
			return nil, diagnostic(Missing, s.ItemID)
		}
		if !symbolIDRE.MatchString(s.ID) || s.Name == "" || len(s.Name) > 256 || !utf8.ValidString(s.Name) || strings.ContainsAny(s.Name, "\x00\r\n") || s.Line < 1 || s.Line > 1000000 || !oneOf(s.State, "declared", "static", "unresolved") {
			return nil, diagnostic(Invalid, "symbol")
		}
		if _, ok := idx.records[s.ID]; ok {
			return nil, diagnostic(Ambiguous, s.ID)
		}
		idx.records[s.ID] = Record{ID: s.ID, Kind: "symbol", ItemID: it.ID, SourceID: it.SourceID, Path: it.SourcePath, Name: s.Name, Line: s.Line, State: s.State}
	}
	return idx, nil
}

// Query fields combine with AND. Empty fields impose no filter. One requests a
// unique lookup; ambiguity is checked before count or byte limits are applied.
type Query struct {
	ID       string
	Kind     string
	SourceID string
	Path     string
	Symbol   string
	Text     string
	One      bool
}

func (i *Index) matches(q Query) ([]Record, error) {
	if i == nil || i.records == nil {
		return nil, diagnostic(Invalid, "index")
	}
	for _, s := range []string{q.ID, q.Kind, q.SourceID, q.Path, q.Symbol, q.Text} {
		if len(s) > 256 || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return nil, diagnostic(Invalid, "query")
		}
	}
	if q.Kind != "" && !oneOf(q.Kind, "block", "skill", "resource", "path", "symbol") {
		return nil, diagnostic(Invalid, "kind")
	}
	result := make([]Record, 0, len(i.records))
	for _, r := range i.records {
		if q.ID != "" && q.ID != r.ID || q.Kind != "" && q.Kind != r.Kind || q.SourceID != "" && q.SourceID != r.SourceID || q.Path != "" && q.Path != r.Path || q.Symbol != "" && (r.Kind != "symbol" || q.Symbol != r.Name) {
			continue
		}
		if q.Text != "" && !strings.Contains(r.ID+"\n"+r.Path+"\n"+r.Name, q.Text) {
			continue
		}
		result = append(result, r)
	}
	sort.Slice(result, func(a, b int) bool { return result[a].ID < result[b].ID })
	if q.One && len(result) == 0 {
		return nil, diagnostic(Missing, "query")
	}
	if q.One && len(result) > 1 {
		return nil, diagnostic(Ambiguous, "query")
	}
	return result, nil
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func clonePacket(p Packet) (Packet, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return Packet{}, err
	}
	var out Packet
	err = json.Unmarshal(raw, &out)
	return out, err
}
