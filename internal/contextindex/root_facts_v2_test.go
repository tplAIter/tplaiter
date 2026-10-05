package contextindex

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

// Pure descriptor data exercises serialization; it never supplies authentication.
// Actual source-bound positive delivery is covered by the installed ROOT proof.
func rootFactPacket(t *testing.T) Packet {
	t.Helper()
	d := catalog(t)
	source := d.Sources[0]
	source.ID = "root:source:installed"
	p := Packet{APIVersion: APIVersion, GraphDigest: evidencecas.Digest([]byte("graph")), Sources: []knowledge.Source{}, Records: []Record{}, Relations: []graphdoc.Edge{}, RequiredFloor: []string{source.ID}, SourceEvidence: []SourceEvidence{{source.ID, source.Anchor.StatementCAS, "source-subject/publisher-evidence/item-bytes-mode"}}, Excerpts: []contextpack.SourceExcerpt{}, ExternalReferences: []Reference{}, TotalMatches: 1}
	p.Sources = append(p.Sources, source)
	for i, path := range []string{"metadata/contract.json", "context/guide.md"} {
		it := d.Items[2]
		it.ID = "root:resource:r-" + strings.Repeat(string(rune('a'+i)), 32)
		it.Kind = "resource"
		it.SourceID = source.ID
		it.SourcePath = path
		it.Requires = []string{}
		it.Produces = []string{}
		it.ContentSHA256 = evidencecas.Digest([]byte(path))
		it.Export = &exports.ExportEntry{ID: "guide", Domain: "block", Name: "guide", Version: "1.0.0", ContentDigest: evidencecas.Digest([]byte("payload")), ToolDigest: evidencecas.Digest([]byte("tool")), Parameters: []exports.ScalarParameter{}, Requires: []exports.ExportRequirement{}}
		p.Records = append(p.Records, Record{it.ID, it.Kind, it.ID, it.SourceID, it.SourcePath, it.ID, 1, "declared", &it})
		p.RequiredFloor = append(p.RequiredFloor, it.ID)
		p.Excerpts = append(p.Excerpts, contextpack.SourceExcerpt{NodeID: it.ID, Path: path, Start: 1, End: 1, Content: path, Digest: it.ContentSHA256})
		p.Relations = append(p.Relations, graphdoc.Edge{From: source.ID, To: it.ID, Kind: "source:anchors", Attributes: map[string]string{"layer": "source", "evidenceState": "declared"}, Provenance: []graphdoc.Provenance{{Declared: true}}})
	}
	for range 32 {
		b, _ := json.Marshal(p)
		if p.Bytes == len(b) {
			return p
		}
		p.Bytes = len(b)
	}
	t.Fatal("packet fixed point")
	return p
}
func TestRootFactsV2CompleteLogicalRoundtrip(t *testing.T) {
	p := rootFactPacket(t)
	f, e := EncodeRootFactsV2(p)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(f)
	decoded, e := DecodeRootFactsV2(wire)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(decoded)
	if !bytes.Equal(a, b) {
		t.Fatal("logical packet changed")
	}
	if len(f.Exports) != 1 || len(f.RelationFacts) != 1 || len(decoded.Records) != 2 || len(decoded.RequiredFloor) != 3 || len(decoded.Excerpts) != 2 || decoded.Bytes != len(a) {
		t.Fatal("shared tables changed logical multiplicity")
	}
	f.DescriptorDefaults.UpdateTriggers[0] = "changed"
	if p.Records[0].Descriptor.UpdateTriggers[0] == "changed" {
		t.Fatal("output aliases caller")
	}
	t.Logf("all logical fields/Bytes exact; shared entry and relation facts preserve both records and endpoints; logical=%d wire=%d", len(a), len(wire))
}
func TestRootFactsV2MalformedMissingAndExpandedCounters(t *testing.T) {
	p := rootFactPacket(t)
	f, e := EncodeRootFactsV2(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f)
	for name, mutate := range map[string]func(map[string]any){
		"missing-zero-count": func(x map[string]any) { delete(x["packet"].(map[string]any), "omittedMatches") },
		"unknown":            func(x map[string]any) { x["authority"] = true },
		"missing-record":     func(x map[string]any) { x["records"] = x["records"].([]any)[:1] },
		"missing-floor":      func(x map[string]any) { x["packet"].(map[string]any)["requiredFloor"] = []any{} },
		"missing-excerpt":    func(x map[string]any) { x["packet"].(map[string]any)["excerpts"] = []any{} },
		"duplicate-record":   func(x map[string]any) { r := x["records"].([]any); r[1] = r[0] },
		"export-reference": func(x map[string]any) {
			x["records"].([]any)[0].(map[string]any)["descriptor"].(map[string]any)["exportRef"] = -1
		},
		"relation-reference": func(x map[string]any) { x["relations"].([]any)[0].(map[string]any)["factRef"] = 99 },
		"changed-source": func(x map[string]any) {
			x["packet"].(map[string]any)["sources"].([]any)[0].(map[string]any)["anchor"].(map[string]any)["commit"] = "changed"
		},
		"unused-table":          func(x map[string]any) { x["exports"] = append(x["exports"].([]any), x["exports"].([]any)[0]) },
		"changed-default":       func(x map[string]any) { x["descriptorDefaults"].(map[string]any)["mode"] = "100755" },
		"changed-logical-bytes": func(x map[string]any) { x["packet"].(map[string]any)["bytes"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(raw, &x)
			mutate(x)
			b, _ := json.Marshal(x)
			if _, e := DecodeRootFactsV2(b); e == nil {
				t.Fatal("malformed facts accepted")
			}
		})
	}
	duplicate := bytes.Replace(raw, []byte(`"apiVersion":`), []byte(`"apiVersion":"duplicate","apiVersion":`), 1)
	if _, e := DecodeRootFactsV2(duplicate); e == nil {
		t.Fatal("duplicate key accepted")
	}
	p.Excerpts[0].Content = strings.Repeat("x", 32769)
	if _, e := EncodeRootFactsV2(p); e == nil {
		t.Fatal("oversized logical packet accepted")
	}
}

func TestRootFactsV2MixedPortableModesPreserved(t *testing.T) {
	p := rootFactPacket(t)
	p.Records[1].Descriptor.Mode = "100755"
	for range 32 {
		raw, _ := json.Marshal(p)
		if p.Bytes == len(raw) {
			break
		}
		p.Bytes = len(raw)
	}
	f, e := EncodeRootFactsV2(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f)
	out, e := DecodeRootFactsV2(raw)
	if e != nil {
		t.Fatal(e)
	}
	if out.Records[0].Descriptor.Mode != "100644" || out.Records[1].Descriptor.Mode != "100755" || !bytes.Equal(wire(t, p), wire(t, out)) {
		t.Fatal("supported image mode lost")
	}
}
