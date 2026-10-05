package contextindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

const RootFactsAPIVersion = "tplaiter.dev/context-index-facts/v2"

// RootFactsV2 is a lossless encoding, never a source authentication carrier.
// All references are bounded table indexes; there are no recursive references.
type RootFactsV2 struct {
	APIVersion         string                 `json:"apiVersion"`
	LogicalSHA256      string                 `json:"logicalSHA256"`
	DescriptorDefaults RootDescriptorDefaults `json:"descriptorDefaults"`
	Exports            []exports.ExportEntry  `json:"exports"`
	Records            []RootFactRecord       `json:"records"`
	RelationFacts      []RootRelationFact     `json:"relationFacts"`
	Relations          []RootFactRelation     `json:"relations"`
	Packet             RootPacketRemainder    `json:"packet"`
}
type RootDescriptorDefaults struct {
	SourceID       string                  `json:"sourceId"`
	Mode           string                  `json:"mode"`
	Ownership      knowledge.Ownership     `json:"ownership"`
	UpdateTriggers []string                `json:"updateTriggers"`
	Requires       []string                `json:"requires"`
	Produces       []string                `json:"produces"`
	Executor       knowledge.Executor      `json:"executor"`
	Inputs         knowledge.InputContract `json:"inputs"`
	Quality        []knowledge.Quality     `json:"quality"`
}
type RootFactDescriptor struct {
	Version       string  `json:"version"`
	SourcePath    string  `json:"sourcePath"`
	ContentSHA256 string  `json:"contentSHA256"`
	ExportRef     *int    `json:"exportRef,omitempty"`
	Mode          *string `json:"mode,omitempty"`
}
type RootFactRecord struct {
	ID         string             `json:"id"`
	Kind       string             `json:"kind"`
	Line       int                `json:"line"`
	State      string             `json:"state"`
	Descriptor RootFactDescriptor `json:"descriptor"`
}
type RootRelationFact struct {
	Kind       string                `json:"kind"`
	Attributes map[string]string     `json:"attributes,omitempty"`
	Provenance []graphdoc.Provenance `json:"provenance,omitempty"`
}
type RootFactRelation struct {
	From    string `json:"from"`
	To      string `json:"to"`
	FactRef int    `json:"factRef"`
}
type RootPacketRemainder struct {
	GraphDigest        string                      `json:"graphDigest"`
	Sources            []knowledge.Source          `json:"sources"`
	ExternalReferences []Reference                 `json:"externalReferences"`
	RequiredFloor      []string                    `json:"requiredFloor"`
	SourceEvidence     []SourceEvidence            `json:"sourceEvidence"`
	Excerpts           []contextpack.SourceExcerpt `json:"excerpts"`
	TotalMatches       int                         `json:"totalMatches"`
	OmittedMatches     int                         `json:"omittedMatches"`
	Bytes              int                         `json:"bytes"`
}

func rootDefaults(d knowledge.Item) RootDescriptorDefaults {
	return RootDescriptorDefaults{d.SourceID, d.Mode, d.Ownership, d.UpdateTriggers, d.Requires, d.Produces, d.Executor, d.Inputs, d.Quality}
}
func rootLogicalDigest(p Packet) (string, error) {
	b, e := canonicaljson.Canonical(p)
	if e != nil {
		return "", e
	}
	return evidencecas.Digest(b), nil
}
func rootPacketInvariant(p Packet) error {
	b, e := json.Marshal(p)
	if e != nil || p.APIVersion != APIVersion || p.Bytes != len(b) || len(b) > contextpack.HardLimit || len(p.Records) < 1 || len(p.Records) > 32 || len(p.Sources) != 1 || len(p.RequiredFloor) != len(p.Records)+1 || len(p.Excerpts) != len(p.Records) || len(p.SourceEvidence) != 1 || len(p.Relations) > 256 || p.TotalMatches != 1 || p.OmittedMatches != 0 || p.ExternalReferences == nil || len(p.ExternalReferences) != 0 {
		return diagnostic(Invalid, "root facts logical packet")
	}
	floor := map[string]bool{}
	for _, id := range p.RequiredFloor {
		if floor[id] {
			return diagnostic(Ambiguous, id)
		}
		floor[id] = true
	}
	source := p.Sources[0]
	if source.ID != "root:source:installed" || !floor[source.ID] || p.SourceEvidence[0].SourceID != source.ID || p.SourceEvidence[0].StatementCAS != source.Anchor.StatementCAS {
		return diagnostic(Invalid, "root source")
	}
	if p.Records[0].Descriptor == nil {
		return diagnostic(Invalid, "root descriptor")
	}
	defaults := rootDefaults(*p.Records[0].Descriptor)
	recordIDs := map[string]bool{}
	for i, r := range p.Records {
		d := r.Descriptor
		if recordIDs[r.ID] {
			return diagnostic(Ambiguous, r.ID)
		}
		recordIDs[r.ID] = true
		if d == nil || !strings.HasPrefix(r.ID, "root:"+r.Kind+":r-") || d.ID != r.ID || d.Kind != r.Kind || r.ItemID != r.ID || r.Name != r.ID || r.SourceID != source.ID || d.SourceID != r.SourceID || r.Path != d.SourcePath || r.Line != 1 || r.State != "declared" || !floor[r.ID] || !rootSharedDefaultsEqual(defaults, rootDefaults(*d)) || (d.Mode != "100644" && d.Mode != "100755") {
			return diagnostic(Invalid, "root record")
		}
		ex := p.Excerpts[i]
		if ex.NodeID != r.ID || ex.Path != r.Path || ex.Digest != d.ContentSHA256 || ex.Start != 1 || ex.End < 1 || ex.End > 8 || len(ex.Content) > 2048 {
			return diagnostic(Invalid, "root excerpt")
		}
	}
	for _, edge := range p.Relations {
		if !floor[edge.From] || !floor[edge.To] {
			return diagnostic(Invalid, "root relation endpoint")
		}
	}
	return nil
}

// EncodeRootFactsV2 owns its output and retains every logical C03 field.
func EncodeRootFactsV2(p Packet) (RootFactsV2, error) {
	if len(p.Records) == 0 || p.Records[0].Descriptor == nil {
		return RootFactsV2{}, diagnostic(Invalid, "root descriptor")
	}
	if e := rootPacketInvariant(p); e != nil {
		return RootFactsV2{}, e
	}
	digest, e := rootLogicalDigest(p)
	if e != nil {
		return RootFactsV2{}, e
	}
	f := RootFactsV2{APIVersion: RootFactsAPIVersion, LogicalSHA256: digest, DescriptorDefaults: rootDefaults(*p.Records[0].Descriptor), Exports: []exports.ExportEntry{}, Records: []RootFactRecord{}, RelationFacts: []RootRelationFact{}, Relations: []RootFactRelation{}, Packet: RootPacketRemainder{p.GraphDigest, p.Sources, p.ExternalReferences, p.RequiredFloor, p.SourceEvidence, p.Excerpts, p.TotalMatches, p.OmittedMatches, p.Bytes}}
	for _, r := range p.Records {
		d := r.Descriptor
		rd := RootFactDescriptor{Version: d.Version, SourcePath: d.SourcePath, ContentSHA256: d.ContentSHA256}
		if d.Mode != f.DescriptorDefaults.Mode {
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
		f.Records = append(f.Records, RootFactRecord{r.ID, r.Kind, r.Line, r.State, rd})
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
		return RootFactsV2{}, e
	}
	var owned RootFactsV2
	e = json.Unmarshal(raw, &owned)
	return owned, e
}

// DecodeRootFactsV2 rejects noncanonical tables, missing/unknown/duplicate keys,
// expansions beyond the unchanged C03 ceiling, and altered logical facts.
func DecodeRootFactsV2(raw []byte) (Packet, error) {
	var f RootFactsV2
	if len(raw) == 0 || len(raw) > contextpack.HardLimit {
		return Packet{}, diagnostic(Budget, "root facts wire")
	}
	if e := canonicaljson.DecodeStrict(raw, &f); e != nil {
		return Packet{}, e
	}
	if e := rootRequiredKeys(raw); e != nil {
		return Packet{}, e
	}
	if f.APIVersion != RootFactsAPIVersion || len(f.Records) < 1 || len(f.Records) > 32 || len(f.Exports) > 16 || len(f.Relations) > 256 || len(f.RelationFacts) > 256 || f.Exports == nil || f.RelationFacts == nil || f.Relations == nil {
		return Packet{}, diagnostic(Invalid, "root facts tables")
	}
	r := f.Packet
	p := Packet{APIVersion: APIVersion, GraphDigest: r.GraphDigest, Records: []Record{}, Sources: r.Sources, Relations: []graphdoc.Edge{}, ExternalReferences: r.ExternalReferences, RequiredFloor: r.RequiredFloor, SourceEvidence: r.SourceEvidence, Excerpts: r.Excerpts, TotalMatches: r.TotalMatches, OmittedMatches: r.OmittedMatches, Bytes: r.Bytes}
	defaults := f.DescriptorDefaults
	for _, rr := range f.Records {
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
	if e := rootPacketInvariant(p); e != nil {
		return Packet{}, e
	}
	hash, e := rootLogicalDigest(p)
	if e != nil || hash != f.LogicalSHA256 {
		return Packet{}, diagnostic(Stale, "root logical digest")
	}
	canonical, e := EncodeRootFactsV2(p)
	if e != nil {
		return Packet{}, e
	}
	a, e := canonicaljson.Canonical(canonical)
	if e != nil {
		return Packet{}, e
	}
	b, e := canonicaljson.Canonicalize(raw)
	if e != nil || !bytes.Equal(a, b) {
		return Packet{}, diagnostic(Invalid, "root fact canonical tables")
	}
	return p, nil
}
func rootRequiredKeys(raw []byte) error {
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
				return fmt.Errorf("root facts array")
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
			return fmt.Errorf("root facts object")
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
	return walk(raw, reflect.TypeOf(RootFactsV2{}))
}

func rootSharedDefaultsEqual(a, b RootDescriptorDefaults) bool {
	a.Mode, b.Mode = "", ""
	return reflect.DeepEqual(a, b)
}
