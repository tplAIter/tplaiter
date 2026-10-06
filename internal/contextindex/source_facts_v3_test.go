package contextindex

import (
	"bytes"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"strings"
	"testing"
)

func sourceFactPacket(t *testing.T) Packet {
	t.Helper()
	p := rootFactPacket(t)
	source := p.Sources[0]
	source.ID = "context:source:dependency"
	source.Pin.Alias = "dependency"
	p.Sources = append(p.Sources, source)
	p.SourceEvidence = append(p.SourceEvidence, SourceEvidence{source.ID, source.Anchor.StatementCAS, "source-subject/publisher-evidence/item-bytes-mode"})
	p.RequiredFloor = append(p.RequiredFloor, source.ID)
	d := *p.Records[1].Descriptor
	d.SourceID = source.ID
	d.Ownership.OwnerID = "dependency:owner:publisher"
	d.UpdateTriggers = []string{"ownership", "dependencies"}
	d.Inputs.ContextFloor = []string{p.Records[0].ID}
	d.Requires = []string{p.Records[0].ID}
	d.Produces = []string{}
	p.Records[1].SourceID = source.ID
	p.Records[1].Descriptor = &d
	p.Relations[1].From = source.ID
	p.Relations = append(p.Relations, graphdoc.Edge{From: p.Records[0].ID, To: d.ID, Kind: "workflow:requires", Attributes: map[string]string{"layer": "workflow"}})
	p.ExternalReferences = append(p.ExternalReferences, Reference{ID: "context:resource:external", State: "unresolved"})
	p.Relations = append(p.Relations, graphdoc.Edge{From: d.ID, To: "context:resource:external", Kind: "semantic:related"})
	sourceFixBytes(t, &p)
	return p
}
func sourceFixBytes(t *testing.T, p *Packet) {
	t.Helper()
	for range 32 {
		b, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		if p.Bytes == len(b) {
			return
		}
		p.Bytes = len(b)
	}
	t.Fatal("packet byte fixed point")
}
func TestSourceFactsV3CompletePerSourceRoundtrip(t *testing.T) {
	p := sourceFactPacket(t)
	f, e := EncodeSourceFactsV3(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f)
	out, e := DecodeSourceFactsV3(raw)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(out)
	if !bytes.Equal(a, b) || len(f.DescriptorDefaults) != 2 || len(f.Exports) != 1 || out.Bytes != len(a) || len(out.SourceEvidence) != 2 || len(out.RequiredFloor) != 4 || len(out.ExternalReferences) != 1 {
		t.Fatal("logical source metadata/counts/bytes lost")
	}
	f.DescriptorDefaults[0].UpdateTriggers[0] = "changed"
	if p.Records[0].Descriptor.UpdateTriggers[0] == "changed" {
		t.Fatal("caller aliases output")
	}
	t.Logf("two source-specific defaults, typed export/relations/complete floor/evidence/excerpts; logical=%d wire=%d", len(a), len(raw))
}
func TestSourceFactsV3StrictTablesFloorAndBudget(t *testing.T) {
	p := sourceFactPacket(t)
	f, e := EncodeSourceFactsV3(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f)
	for name, mutate := range map[string]func(map[string]any){
		"missing-ref":      func(x map[string]any) { delete(x["records"].([]any)[0].(map[string]any), "defaultsRef") },
		"negative-ref":     func(x map[string]any) { x["records"].([]any)[0].(map[string]any)["defaultsRef"] = -1 },
		"out-of-range":     func(x map[string]any) { x["records"].([]any)[0].(map[string]any)["defaultsRef"] = 100 },
		"unknown":          func(x map[string]any) { x["grant"] = true },
		"missing-zero":     func(x map[string]any) { delete(x["packet"].(map[string]any), "omittedMatches") },
		"duplicate-source": func(x map[string]any) { s := x["packet"].(map[string]any)["sources"].([]any); s[1] = s[0] },
		"foreign-evidence": func(x map[string]any) { s := x["packet"].(map[string]any)["sourceEvidence"].([]any); s[1] = s[0] },
		"missing-floor":    func(x map[string]any) { x["packet"].(map[string]any)["requiredFloor"] = []any{} },
		"missing-excerpt":  func(x map[string]any) { x["packet"].(map[string]any)["excerpts"] = []any{} },
		"unused-defaults": func(x map[string]any) {
			d := x["descriptorDefaults"].([]any)
			x["descriptorDefaults"] = append(d, d[0])
		},
		"unused-export":  func(x map[string]any) { d := x["exports"].([]any); x["exports"] = append(d, d[0]) },
		"fractional-ref": func(x map[string]any) { x["records"].([]any)[0].(map[string]any)["defaultsRef"] = 0.5 },
		"table-permutation": func(x map[string]any) {
			d := x["descriptorDefaults"].([]any)
			d[0], d[1] = d[1], d[0]
			for _, v := range x["records"].([]any) {
				r := v.(map[string]any)
				r["defaultsRef"] = 1 - r["defaultsRef"].(float64)
			}
		},
		"missing-external": func(x map[string]any) { x["packet"].(map[string]any)["externalReferences"] = []any{} },
		"external-floor-alias": func(x map[string]any) {
			x["packet"].(map[string]any)["externalReferences"].([]any)[0].(map[string]any)["id"] = x["packet"].(map[string]any)["requiredFloor"].([]any)[0]
		},
		"wrong-bytes": func(x map[string]any) { x["packet"].(map[string]any)["bytes"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(raw, &x)
			mutate(x)
			bad, _ := json.Marshal(x)
			if _, e := DecodeSourceFactsV3(bad); e == nil {
				t.Fatal("invalid facts accepted")
			}
		})
	}
	dup := bytes.Replace(raw, []byte(`"defaultsRef":`), []byte(`"defaultsRef":0,"defaultsRef":`), 1)
	minusZero := bytes.Replace(raw, []byte(`"defaultsRef":0`), []byte(`"defaultsRef":-0`), 1)
	if _, e := DecodeSourceFactsV3(minusZero); e == nil {
		t.Fatal("negative zero reference accepted")
	}
	if _, e := DecodeSourceFactsV3(dup); e == nil {
		t.Fatal("duplicate ref accepted")
	}
	p.Excerpts[0].Content = strings.Repeat("x", 32769)
	sourceFixBytes(t, &p)
	if _, e := EncodeSourceFactsV3(p); e == nil {
		t.Fatal("whole logical cap raised")
	}
	p = sourceFactPacket(t)
	p.Sources = p.Sources[:1]
	sourceFixBytes(t, &p)
	if _, e := EncodeSourceFactsV3(p); e == nil {
		t.Fatal("v3 accepted singleton instead of unchanged v2")
	}
}
