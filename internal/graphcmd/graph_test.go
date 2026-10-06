package graphcmd

import (
	"context"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/semanticgraph"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"reflect"
	"strings"
	"testing"
)

func graphPin(alias string, dependencies ...string) deps.PinnedSource {
	return deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: "provider." + alias, Origin: "https://example.test/" + alias, TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat("1", 40), TreeDigest: "sha256:" + strings.Repeat("2", 64), ContentDigest: "sha256:" + strings.Repeat("3", 64), ContractDigest: "sha256:" + strings.Repeat("4", 64), EvidenceDigest: "sha256:" + strings.Repeat("5", 64), Parameters: []deps.Parameter{}, Dependencies: append([]string{}, dependencies...)}
}
func TestNativeGraphDiamondProjectionAndSelectorCounters(t *testing.T) {
	pins := []deps.PinnedSource{graphPin("root", "a", "b"), graphPin("a", "leaf"), graphPin("b", "leaf"), graphPin("leaf")}
	g, e := deps.BuildSourceGraph(pins)
	if e != nil {
		t.Fatal(e)
	}
	records, e := sourceRecords(*g, pins)
	if e != nil || len(records) != 8 {
		t.Fatal("lost source pins/diamond", e)
	}
	keys := map[string]string{}
	for _, n := range g.Nodes {
		for _, v := range n.Provenance {
			keys[v.Alias] = n.Key
		}
	}
	cs := []exports.Catalog{}
	for _, p := range pins {
		req := []exports.ExportRequirement{}
		for _, d := range p.Dependencies {
			req = append(req, exports.ExportRequirement{Selector: d + ".block.notes", ContractDigest: p.ContractDigest, CompatibleRange: "*"})
		}
		cs = append(cs, exports.Catalog{APIVersion: exports.CatalogAPIVersion, Source: keys[p.Alias], Provider: p.ProviderID, ContractDigest: p.ContractDigest, Exports: []exports.ExportEntry{{ID: "same-id", Domain: "block", Name: "notes", Version: "1.0.0", ContentDigest: p.ContentDigest, ToolDigest: p.TreeDigest, Parameters: []exports.ScalarParameter{}, Requires: req}}})
	}
	selection := func(s string) exports.Selection {
		return exports.Selection{APIVersion: exports.SelectionAPIVersion, Selector: s, Bindings: []exports.ScalarParameter{}}
	}
	first, e := exports.ResolveSelections([]exports.Selection{selection("a.block.notes"), selection("b.block.notes")}, g, cs)
	if e != nil {
		t.Fatal(e)
	}
	second, e := exports.ResolveSelections([]exports.Selection{selection("b.block.notes"), selection("a.block.notes")}, g, cs)
	if e != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("permutation changed required closure", e)
	}
	out, e := exportRecords(first)
	if e != nil || len(out) != 5 || out[0].Identity == out[1].Identity {
		t.Fatal("collapsed complete identities/edges", e)
	}
	for _, r := range out {
		if r.Export != nil && r.Export.Provider == "provider.leaf" && len(r.Export.Chains) != 2 {
			t.Fatal("transitive chains lost")
		}
	}
	for _, selections := range [][]exports.Selection{{selection("a.block.notes"), selection("a.block.notes")}, {selection("missing.block.notes")}} {
		if _, e = exports.ResolveSelections(selections, g, cs); e == nil {
			t.Fatal("accepted unknown/duplicate selection")
		}
	}
	cs[3].Exports = nil
	if _, e = exports.ResolveSelections([]exports.Selection{selection("a.block.notes")}, g, cs); e == nil {
		t.Fatal("accepted missing prerequisite")
	}
	pins[3].Dependencies = []string{"root"}
	if _, e = deps.BuildSourceGraph(pins); e == nil {
		t.Fatal("accepted source cycle")
	}
}
func TestRegisteredEnvelopeWholeBoundaryPagesAndStaleCursor(t *testing.T) {
	q := Query{Layer: "ast", Representation: "whole", MaxBytes: 32768}
	if e := q.Normalize(); e != nil {
		t.Fatal(e)
	}
	d := resultdto.GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: "ast", QueryDigest: hashValue("query"), InputDigests: []string{}, FullGraphDigest: hashValue("graph"), ObservationBasis: "installed-project-syntax", VerificationLevel: "syntax", CacheState: "disabled", GraphStatus: "ok", Records: []resultdto.GraphRecord{}}
	for i := 0; i < 5; i++ {
		d.Records = append(d.Records, resultdto.GraphRecord{Kind: "ast-node", Identity: strings.Repeat("<\"&", 180) + string(rune('a'+i))})
	}
	raw, e := makeFrame(d, q, "project", "/public/<root>&\\path", "version")
	if e != nil {
		t.Fatal(e)
	}
	q.MaxBytes = len(raw)
	exact, e := makeFrame(d, q, "project", "/public/<root>&\\path", "version")
	if e != nil || string(exact) != string(raw) {
		t.Fatal("exact ceiling mismatch", e)
	}
	q.MaxBytes--
	if _, e = makeFrame(d, q, "project", "/public/<root>&\\path", "version"); Code(e) != "GRAPH_OUTPUT_BUDGET" {
		t.Fatal("accepted one below", e)
	}
	q.Representation = "page"
	q.MaxBytes = 32768
	q.Limit = 2
	raw, e = makeFrame(d, q, "project", "/root", "version")
	if e != nil {
		t.Fatal(e)
	}
	env, e := resultdto.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	var page resultdto.GraphData
	if e = json.Unmarshal(env.Data, &page); e != nil || page.Page.Returned != 2 || page.Page.Omitted != 3 || page.Page.NextCursor == "" {
		t.Fatal("dishonest page", e)
	}
	q.Cursor = page.Page.NextCursor
	d.FullGraphDigest = hashValue("changed")
	if _, e = makeFrame(d, q, "project", "/root", "version"); Code(e) != "GRAPH_CURSOR_STALE" {
		t.Fatal("accepted stale cursor", e)
	}
	if _, e = Prepare(context.Background(), nil, Query{Layer: "source"}, runtimeassembly.Options{}); e == nil {
		t.Fatal("nil runtime accepted")
	}
}

func TestActualSyntaxMCPWholeBoundaryAndPage(t *testing.T) {
	g, err := semanticgraph.AnalyzeFiles(context.Background(), []semanticgraph.SourceFile{{Path: "service.go", Bytes: []byte("package service\nfunc First() {}\nfunc Second() {}\nfunc Third() {}\n")}}, semanticgraph.Options{})
	if err != nil {
		t.Fatal(err)
	}
	records, err := astRecords(g)
	if err != nil {
		t.Fatal(err)
	}
	q := Query{Layer: "ast", Representation: "whole", MaxBytes: 32768, Limit: 256}
	if err = q.Normalize(); err != nil {
		t.Fatal(err)
	}
	d := resultdto.GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: "ast", QueryDigest: hashValue(q), InputDigests: []string{}, FullGraphDigest: g.Digest, ObservationBasis: "installed-project-syntax", VerificationLevel: "syntax-go-and-approximate-rust-outline", CacheState: "disabled", GraphStatus: g.Status, Records: records, Stats: map[string]resultdto.GraphLayerStats{}}
	id, _ := json.Marshal("<\\\"&\n\té")
	layout := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: id, Ceiling: 32768}
	raw, err := makeFrameLayout(d, q, "p", "/public/<root>&", "test", &layout)
	if err != nil {
		t.Fatal(err)
	}
	env, err := resultdto.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := resultwire.Frame(layout.RequestID(), resultwire.Structured(env, false))
	if err != nil {
		t.Fatal(err)
	}
	q.MaxBytes = len(wire)
	layout.Ceiling = q.MaxBytes
	exact, err := makeFrameLayout(d, q, "p", "/public/<root>&", "test", &layout)
	if err != nil {
		t.Fatal("exact MCP whole ceiling", err)
	}
	if string(exact) != string(raw) {
		t.Fatal("boundary changed ordinary complete records")
	}
	q.MaxBytes--
	layout.Ceiling = q.MaxBytes
	if _, err = makeFrameLayout(d, q, "p", "/public/<root>&", "test", &layout); Code(err) != "GRAPH_OUTPUT_BUDGET" {
		t.Fatal("one below whole accepted", err)
	}
	q.Representation = "page"
	q.MaxBytes -= 63
	layout.Ceiling = q.MaxBytes
	raw, err = makeFrameLayout(d, q, "p", "/public/<root>&", "test", &layout)
	if err != nil {
		t.Fatal(err)
	}
	env, err = resultdto.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var page resultdto.GraphData
	if err = json.Unmarshal(env.Data, &page); err != nil || page.Page.Returned >= len(records) || page.Page.Returned < 1 || page.Page.Total != len(records) || page.Page.NextCursor == "" {
		t.Fatal("page omitted metadata/records", err)
	}
	wire, err = resultwire.Frame(layout.RequestID(), resultwire.Structured(env, false))
	if err != nil || len(wire) > layout.Ceiling {
		t.Fatal("actual MCP page overflow", err)
	}
	q.Cursor = page.Page.NextCursor
	if _, err = makeFrameLayout(d, q, "p", "/public/<root>&", "test", &layout); err != nil {
		t.Fatal("digest-bound next cursor unusable", err)
	}
	t.Logf("actual syntax %d complete facts, MCP whole minimum=%d, one below refuses, page=%d bytes", len(records), layout.Ceiling+1, len(wire))
}
