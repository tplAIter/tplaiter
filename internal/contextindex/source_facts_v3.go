package contextindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

const SourceFactsAPIVersion = "tplaiter.dev/context-index-facts/v3"

// SourceFactsV3 is a lossless multi-source data encoding, never an authentication carrier.
// All references are bounded table indexes; there are no recursive references.
type SourceFactsV3 struct {
	APIVersion         string                   `json:"apiVersion"`
	LogicalSHA256      string                   `json:"logicalSHA256"`
	DescriptorDefaults []RootDescriptorDefaults `json:"descriptorDefaults"`
	Exports            []exports.ExportEntry    `json:"exports"`
	Records            []SourceFactRecord       `json:"records"`
	RelationFacts      []RootRelationFact       `json:"relationFacts"`
	Relations          []RootFactRelation       `json:"relations"`
	Packet             RootPacketRemainder      `json:"packet"`
}

// SourceFactRecord binds a complete record to its source-specific defaults.
type SourceFactRecord struct {
	ID          string             `json:"id"`
	Kind        string             `json:"kind"`
	Line        int                `json:"line"`
	State       string             `json:"state"`
	DefaultsRef int                `json:"defaultsRef"`
	Descriptor  RootFactDescriptor `json:"descriptor"`
}

func sourcePacketInvariant(p Packet) error {
	raw, err := json.Marshal(p)
	if err != nil || p.APIVersion != APIVersion || p.Bytes != len(raw) || len(raw) > contextpack.HardLimit || len(p.Sources) < 2 || len(p.Sources) > 32 || len(p.Records) < 2 || len(p.Records) > 32 || len(p.RequiredFloor) != len(p.Sources)+len(p.Records) || len(p.SourceEvidence) != len(p.Sources) || len(p.Excerpts) != len(p.Records) || len(p.Relations) > 256 || p.TotalMatches < 1 || p.OmittedMatches < 0 || p.OmittedMatches >= p.TotalMatches || p.TotalMatches-p.OmittedMatches > len(p.Records) || p.ExternalReferences == nil {
		return diagnostic(Invalid, "source facts logical packet")
	}
	floor := map[string]bool{}
	for _, id := range p.RequiredFloor {
		if floor[id] {
			return diagnostic(Ambiguous, id)
		}
		floor[id] = true
	}
	sources := map[string]knowledge.Source{}
	for i, source := range p.Sources {
		if _, exists := sources[source.ID]; exists || !floor[source.ID] || source.ID == "" {
			return diagnostic(Invalid, "source identity")
		}
		ev := p.SourceEvidence[i]
		if ev.SourceID != source.ID || ev.StatementCAS != source.Anchor.StatementCAS || ev.Scope != "source-subject/publisher-evidence/item-bytes-mode" {
			return diagnostic(Invalid, "source evidence mapping")
		}
		sources[source.ID] = source
	}
	records := map[string]bool{}
	used := map[string]bool{}
	for i, r := range p.Records {
		d := r.Descriptor
		if records[r.ID] || sources[r.ID].ID != "" {
			return diagnostic(Ambiguous, r.ID)
		}
		records[r.ID] = true
		if d == nil || d.ID != r.ID || d.Kind != r.Kind || r.ItemID != r.ID || r.Name != r.ID || sources[r.SourceID].ID == "" || d.SourceID != r.SourceID || r.Path != d.SourcePath || r.Line != 1 || r.State != "declared" || !floor[r.ID] || (d.Mode != "100644" && d.Mode != "100755") {
			return diagnostic(Invalid, "source record")
		}
		used[r.SourceID] = true
		ex := p.Excerpts[i]
		if ex.NodeID != r.ID || ex.Path != r.Path || ex.Digest != d.ContentSHA256 || ex.Start != 1 || ex.End < 1 || ex.End > 8 || len(ex.Content) > 2048 {
			return diagnostic(Invalid, "source excerpt")
		}
	}
	if len(used) != len(sources) {
		return diagnostic(Invalid, "unobserved source")
	}
	external := map[string]bool{}
	for _, ref := range p.ExternalReferences {
		if ref.ID == "" || floor[ref.ID] || external[ref.ID] || (ref.State != "declared" && ref.State != "static" && ref.State != "unresolved") {
			return diagnostic(Invalid, "external reference")
		}
		external[ref.ID] = true
	}
	usedExternal := map[string]bool{}
	for _, edge := range p.Relations {
		if (!floor[edge.From] && !external[edge.From]) || (!floor[edge.To] && !external[edge.To]) || (!floor[edge.From] && !floor[edge.To]) {
			return diagnostic(Invalid, "source relation endpoint")
		}
		if external[edge.From] {
			usedExternal[edge.From] = true
		}
		if external[edge.To] {
			usedExternal[edge.To] = true
		}
	}
	if len(usedExternal) != len(external) {
		return diagnostic(Invalid, "unreferenced external record")
	}

	// Validate all public source/item facets without manufacturing observations.
	catalog := knowledge.Catalog{Kind: "KnowledgeCatalog", ID: "context:catalog:source-facts", Version: "1.0.0", APIVersion: knowledge.APIVersion, Sources: p.Sources, Items: []knowledge.Item{}, Edges: []knowledge.Edge{}}
	for _, r := range p.Records {
		catalog.Items = append(catalog.Items, *r.Descriptor)
	}
	if err := knowledge.Validate(catalog); err != nil {
		return err
	}
	return nil
}

// EncodeSourceFactsV3 owns its output and retains every logical C03 field.
func EncodeSourceFactsV3(p Packet) (SourceFactsV3, error) {
	if len(p.Records) == 0 || p.Records[0].Descriptor == nil {
		return SourceFactsV3{}, diagnostic(Invalid, "source descriptor")
	}
	if e := sourcePacketInvariant(p); e != nil {
		return SourceFactsV3{}, e
	}
	digest, e := rootLogicalDigest(p)
	if e != nil {
		return SourceFactsV3{}, e
	}
	f := SourceFactsV3{APIVersion: SourceFactsAPIVersion, LogicalSHA256: digest, DescriptorDefaults: []RootDescriptorDefaults{}, Exports: []exports.ExportEntry{}, Records: []SourceFactRecord{}, RelationFacts: []RootRelationFact{}, Relations: []RootFactRelation{}, Packet: RootPacketRemainder{p.GraphDigest, p.Sources, p.ExternalReferences, p.RequiredFloor, p.SourceEvidence, p.Excerpts, p.TotalMatches, p.OmittedMatches, p.Bytes}}
	for _, r := range p.Records {
		d := r.Descriptor
		defaults := rootDefaults(*d)
		defaultsRef := -1
		for i, x := range f.DescriptorDefaults {
			if reflect.DeepEqual(x, defaults) {
				defaultsRef = i
				break
			}
		}
		if defaultsRef < 0 {
			defaultsRef = len(f.DescriptorDefaults)
			f.DescriptorDefaults = append(f.DescriptorDefaults, defaults)
		}
		rd := RootFactDescriptor{Version: d.Version, SourcePath: d.SourcePath, ContentSHA256: d.ContentSHA256}
		if d.Mode != defaults.Mode {
			mode := d.Mode
			rd.Mode = &mode
		}
		if d.Export != nil {
			ix := -1
			for i, x := range f.Exports {
				if reflect.DeepEqual(x, *d.Export) {
					ix = i
					break
				}
			}
			if ix < 0 {
				ix = len(f.Exports)
				f.Exports = append(f.Exports, *d.Export)
			}
			rd.ExportRef = &ix
		}
		f.Records = append(f.Records, SourceFactRecord{r.ID, r.Kind, r.Line, r.State, defaultsRef, rd})
	}
	for _, e := range p.Relations {
		fact := RootRelationFact{e.Kind, e.Attributes, e.Provenance}
		ix := -1
		for i, x := range f.RelationFacts {
			if reflect.DeepEqual(fact, x) {
				ix = i
				break
			}
		}
		if ix < 0 {
			ix = len(f.RelationFacts)
			f.RelationFacts = append(f.RelationFacts, fact)
		}
		f.Relations = append(f.Relations, RootFactRelation{e.From, e.To, ix})
	}
	// The raw decoder checks table canonicality and returns no aliases to p.
	raw, e := json.Marshal(f)
	if e != nil {
		return SourceFactsV3{}, e
	}
	if len(raw) > contextpack.HardLimit {
		return SourceFactsV3{}, diagnostic(Budget, "source facts wire")
	}
	var owned SourceFactsV3
	e = json.Unmarshal(raw, &owned)
	return owned, e
}

// DecodeSourceFactsV3 rejects noncanonical tables, missing/unknown/duplicate keys,
// expansions beyond the unchanged C03 ceiling, and altered logical facts.
func DecodeSourceFactsV3(raw []byte) (Packet, error) {
	var f SourceFactsV3
	if len(raw) == 0 || len(raw) > contextpack.HardLimit {
		return Packet{}, diagnostic(Budget, "source facts wire")
	}
	if e := sourceIntegerLexemes(raw); e != nil {
		return Packet{}, e
	}
	if e := canonicaljson.DecodeStrict(raw, &f); e != nil {
		return Packet{}, e
	}
	if e := sourceRequiredKeys(raw); e != nil {
		return Packet{}, e
	}
	if f.APIVersion != SourceFactsAPIVersion || len(f.Records) < 2 || len(f.Records) > 32 || len(f.Exports) > 32 || len(f.Relations) > 256 || len(f.RelationFacts) > 256 || len(f.DescriptorDefaults) < 2 || len(f.DescriptorDefaults) > 32 || f.Exports == nil || f.RelationFacts == nil || f.Relations == nil {
		return Packet{}, diagnostic(Invalid, "source facts tables")
	}
	r := f.Packet
	p := Packet{APIVersion: APIVersion, GraphDigest: r.GraphDigest, Records: []Record{}, Sources: r.Sources, Relations: []graphdoc.Edge{}, ExternalReferences: r.ExternalReferences, RequiredFloor: r.RequiredFloor, SourceEvidence: r.SourceEvidence, Excerpts: r.Excerpts, TotalMatches: r.TotalMatches, OmittedMatches: r.OmittedMatches, Bytes: r.Bytes}
	for _, rr := range f.Records {
		if rr.DefaultsRef < 0 || rr.DefaultsRef >= len(f.DescriptorDefaults) {
			return Packet{}, diagnostic(Invalid, "defaults reference")
		}
		defaults := f.DescriptorDefaults[rr.DefaultsRef]
		rd := rr.Descriptor
		d := knowledge.Item{ID: rr.ID, Kind: rr.Kind, Version: rd.Version, SourceID: defaults.SourceID, SourcePath: rd.SourcePath, ContentSHA256: rd.ContentSHA256, Mode: defaults.Mode, Ownership: defaults.Ownership, UpdateTriggers: defaults.UpdateTriggers, Requires: defaults.Requires, Produces: defaults.Produces, Executor: defaults.Executor, Inputs: defaults.Inputs, Quality: defaults.Quality}
		if rd.Mode != nil {
			d.Mode = *rd.Mode
		}
		if rd.ExportRef != nil {
			ix := *rd.ExportRef
			if ix < 0 || ix >= len(f.Exports) {
				return Packet{}, diagnostic(Invalid, "export reference")
			}
			x := f.Exports[ix]
			d.Export = &x
		}
		p.Records = append(p.Records, Record{rr.ID, rr.Kind, rr.ID, d.SourceID, d.SourcePath, rr.ID, rr.Line, rr.State, &d})
	}
	for _, rr := range f.Relations {
		if rr.FactRef < 0 || rr.FactRef >= len(f.RelationFacts) {
			return Packet{}, diagnostic(Invalid, "relation reference")
		}
		x := f.RelationFacts[rr.FactRef]
		p.Relations = append(p.Relations, graphdoc.Edge{From: rr.From, To: rr.To, Kind: x.Kind, Attributes: x.Attributes, Provenance: x.Provenance})
	}
	if e := sourcePacketInvariant(p); e != nil {
		return Packet{}, e
	}
	hash, e := rootLogicalDigest(p)
	if e != nil || hash != f.LogicalSHA256 {
		return Packet{}, diagnostic(Stale, "source logical digest")
	}
	canonical, e := EncodeSourceFactsV3(p)
	if e != nil {
		return Packet{}, e
	}
	a, e := canonicaljson.Canonical(canonical)
	if e != nil {
		return Packet{}, e
	}
	b, e := canonicaljson.Canonicalize(raw)
	if e != nil || !bytes.Equal(a, b) {
		return Packet{}, diagnostic(Invalid, "source fact canonical tables")
	}
	return p, nil
}
func sourceRequiredKeys(raw []byte) error {
	// Required zero-valued fields must not silently normalize omitted data.
	var walk func(json.RawMessage, reflect.Type) error
	walk = func(b json.RawMessage, t reflect.Type) error {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() == reflect.Slice {
			if t.Elem().Kind() == reflect.Uint8 {
				return nil
			}
			var values []json.RawMessage
			if json.Unmarshal(b, &values) != nil {
				return fmt.Errorf("source facts array")
			}
			for _, v := range values {
				if e := walk(v, t.Elem()); e != nil {
					return e
				}
			}
			return nil
		}
		if t.Kind() != reflect.Struct {
			return nil
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil {
			return fmt.Errorf("source facts object")
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "" || tag[0] == "-" {
				continue
			}
			v, ok := fields[tag[0]]
			if !ok {
				if strings.Contains(field.Tag.Get("json"), "omitempty") {
					continue
				}
				return diagnostic(Missing, tag[0])
			}
			if e := walk(v, field.Type); e != nil {
				return e
			}
		}
		return nil
	}
	return walk(raw, reflect.TypeOf(SourceFactsV3{}))
}

// Validate original integer lexemes before canonical JSON normalizes -0.
func sourceIntegerLexemes(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(v any) error {
		switch x := v.(type) {
		case json.Number:
			n, e := strconv.ParseInt(x.String(), 10, 64)
			if e != nil || strconv.FormatInt(n, 10) != x.String() || n < -(1<<53)+1 || n > (1<<53)-1 {
				return diagnostic(Invalid, "integer lexeme")
			}
		case map[string]any:
			for _, v := range x {
				if e := walk(v); e != nil {
					return e
				}
			}
		case []any:
			for _, v := range x {
				if e := walk(v); e != nil {
					return e
				}
			}
		}
		return nil
	}
	return walk(value)
}
