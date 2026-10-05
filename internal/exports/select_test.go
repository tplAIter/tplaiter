package exports

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

func batchCatalogFixture(t *testing.T) (Catalog, *deps.SourceGraph) {
	t.Helper()
	c := catalogFixture()
	c.Exports = []ExportEntry{
		{ID: "floor", Domain: "block", Name: "floor", Version: "1.0.0", ContentDigest: exportDigest('c'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('d'), Requires: []ExportRequirement{}},
		{ID: "skill", Domain: "skill", Name: "skill", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{{Selector: "base.block.floor", ContractDigest: c.ContractDigest, CompatibleRange: ">=1.0.0 <2.0.0"}}},
		{ID: "approach", Domain: "approach", Name: "approach", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{{Selector: "base.block.floor", ContractDigest: c.ContractDigest, CompatibleRange: ">=1.0.0 <2.0.0"}}},
	}
	sort.Slice(c.Exports, func(i, j int) bool { return eKey(c.Exports[i]) < eKey(c.Exports[j]) })
	g := bindCatalog(t, &c)
	return c, g
}

func deepSharedBatchFixture(t *testing.T) (*deps.SourceGraph, []Catalog) {
	t.Helper()
	aliases := []string{"a", "b", "middle", "leaf", "tail"}
	children := map[string]string{"a": "middle", "b": "middle", "middle": "leaf", "leaf": "tail"}
	pins := []deps.PinnedSource{}
	for i, alias := range aliases {
		p := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: alias, Origin: "https://example.test/" + alias, TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat(string(byte('a'+i)), 40), TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: exportDigest('3'), EvidenceDigest: exportDigest('4'), Parameters: []deps.Parameter{}, Dependencies: []string{}}
		if child := children[alias]; child != "" {
			p.Dependencies = []string{child}
		}
		pins = append(pins, p)
	}
	sources, err := deps.BuildSourceGraph(pins)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, node := range sources.Nodes {
		keys[node.Identity.ProviderID] = node.Key
	}
	catalogs := []Catalog{}
	for _, alias := range aliases {
		entry := ExportEntry{ID: alias, Domain: "block", Name: alias, Version: "1.0.0", ContentDigest: exportDigest('5'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('6'), Requires: []ExportRequirement{}}
		if child := children[alias]; child != "" {
			entry.Requires = []ExportRequirement{{Selector: child + ".block." + child, ContractDigest: exportDigest('3'), CompatibleRange: ">=1.0.0 <2.0.0"}}
		}
		catalogs = append(catalogs, Catalog{APIVersion: CatalogAPIVersion, Provider: alias, Source: keys[alias], ContractDigest: exportDigest('3'), Exports: []ExportEntry{entry}})
	}
	return sources, catalogs
}

func TestStageABatchTransitiveSharedChains(t *testing.T) {
	sources, catalogs := deepSharedBatchFixture(t)
	a := Selection{SelectionAPIVersion, "a.block.a", []ScalarParameter{}}
	b := Selection{SelectionAPIVersion, "b.block.b", []ScalarParameter{}}
	forward, err := ResolveSelections([]Selection{a, b}, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := ResolveSelections([]Selection{b, a}, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("forward=%s reverse=%s", forward.Digest, reverse.Digest)
	want := map[string][][]string{
		"a": {{"a"}}, "b": {{"b"}},
		"middle": {{"a", "middle"}, {"b", "middle"}},
		"leaf":   {{"a", "middle", "leaf"}, {"b", "middle", "leaf"}},
		"tail":   {{"a", "middle", "leaf", "tail"}, {"b", "middle", "leaf", "tail"}},
	}
	if len(forward.Selected) != 5 || len(forward.Edges) != 4 {
		t.Fatalf("incomplete closure: %+v", forward)
	}
	byID := map[string]SelectedExport{}
	emptyBinding, err := parameterDigest([]ScalarParameter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range forward.Selected {
		byID[record.ID] = record
		for _, catalog := range catalogs {
			if catalog.Provider == record.Provider && (record.Source != catalog.Source || record.ContractDigest != catalog.ContractDigest || record.ContentDigest != catalog.Exports[0].ContentDigest || record.ToolDigest != catalog.Exports[0].ToolDigest || record.Version != catalog.Exports[0].Version) {
				t.Fatalf("lost declared source/export pins: %+v", record)
			}
		}
		if record.BindingSHA256 != emptyBinding || record.SourceParameterSHA256 != emptyBinding || !reflect.DeepEqual(record.Parameters, []ScalarParameter{}) {
			t.Fatalf("lost source/selection parameter binding: %+v", record)
		}
	}
	nodeKey := func(record SelectedExport) string {
		return record.Source + "\x00" + record.Provider + "\x00" + record.Domain + "\x00" + record.ID
	}
	wantEdges := map[ExportEdge]bool{}
	for consumer, dependency := range map[string]string{"a": "middle", "b": "middle", "middle": "leaf", "leaf": "tail"} {
		wantEdges[ExportEdge{Dependency: nodeKey(byID[dependency]), Consumer: nodeKey(byID[consumer])}] = true
	}
	for _, edge := range forward.Edges {
		if !wantEdges[edge] {
			t.Fatalf("unexpected dependency edge: %+v", edge)
		}
		delete(wantEdges, edge)
	}
	if len(wantEdges) != 0 {
		t.Fatalf("missing dependency edges: %+v", wantEdges)
	}
	for _, graph := range []ExportGraph{forward, reverse} {
		for _, record := range graph.Selected {
			if !reflect.DeepEqual(record.Chains, want[record.ID]) {
				t.Errorf("%s lost transitive provenance: got %v want %v", record.ID, record.Chains, want[record.ID])
			}
			if _, err := SelectedExportIdentity(record); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatal("complete batch graph/pins/chains/edges/order/digest depend on request order")
	}
	reversedCatalogs := append([]Catalog(nil), catalogs...)
	for i, j := 0, len(reversedCatalogs)-1; i < j; i, j = i+1, j-1 {
		reversedCatalogs[i], reversedCatalogs[j] = reversedCatalogs[j], reversedCatalogs[i]
	}
	permuted, err := ResolveSelections([]Selection{b, a}, sources, reversedCatalogs)
	if err != nil || !reflect.DeepEqual(forward, permuted) {
		t.Fatalf("catalog permutation changed complete graph: %+v %v", permuted, err)
	}
	// Requesting an already required root as well must not omit its new path
	// from any of the deeper prerequisite records.
	middle := Selection{SelectionAPIVersion, "middle.block.middle", []ScalarParameter{}}
	extra, err := ResolveSelections([]Selection{a, b, middle}, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range extra.Selected {
		if record.ID == "tail" && !reflect.DeepEqual(record.Chains, [][]string{{"a", "middle", "leaf", "tail"}, {"b", "middle", "leaf", "tail"}, {"middle", "leaf", "tail"}}) {
			t.Fatalf("cached root tail chains: %v", record.Chains)
		}
	}
	extraReverse, err := ResolveSelections([]Selection{middle, b, a}, sources, catalogs)
	if err != nil || !reflect.DeepEqual(extra, extraReverse) {
		t.Fatalf("cached root permutation: %+v %v", extraReverse, err)
	}
}

func TestStageABatchSingleRootSharedChains(t *testing.T) {
	sources, catalogs := deepSharedBatchFixture(t)
	for i := range catalogs {
		if catalogs[i].Provider == "a" {
			top := catalogs[i].Exports[0]
			top.ID = "top"
			top.Name = "top"
			top.Requires = []ExportRequirement{{Selector: "a.block.a", ContractDigest: catalogs[i].ContractDigest, CompatibleRange: "*"}, {Selector: "b.block.b", ContractDigest: catalogs[i].ContractDigest, CompatibleRange: "*"}}
			catalogs[i].Exports = append(catalogs[i].Exports, top)
		}
	}
	request := Selection{SelectionAPIVersion, "a.block.top", []ScalarParameter{}}
	legacy, err := ResolveSelection(request, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LEGACY_DEEP_WIRE=%s digest=%s", digestBytes(wire), legacy.Digest)
	if digestBytes(wire) != "sha256:544b1a55c6255fcb3b43f1f688bc4d7e39b0288eb623849619a10ace732fdb52" || legacy.Digest != "sha256:9c4fc1454c464767320e36dc93bdbe4743ac218a6129e4b73fc735b50118e88b" {
		t.Fatalf("legacy deep single-selection wire changed: %s", wire)
	}
	batch, err := ResolveSelections([]Selection{request}, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Selected) != 6 || len(batch.Edges) != 6 {
		t.Fatalf("single-root closure incomplete: %+v", batch)
	}
	for _, record := range batch.Selected {
		if record.ID == "tail" && !reflect.DeepEqual(record.Chains, [][]string{{"a", "a", "middle", "leaf", "tail"}, {"a", "b", "middle", "leaf", "tail"}}) {
			t.Fatalf("single-root batch omitted transitive path: %v", record.Chains)
		}
	}
}

func TestStageABatchDeepSharedGuards(t *testing.T) {
	for _, kind := range []string{"contract", "range", "missing", "cycle", "bindings"} {
		t.Run(kind, func(t *testing.T) {
			sources, catalogs := deepSharedBatchFixture(t)
			requests := []Selection{{SelectionAPIVersion, "a.block.a", []ScalarParameter{}}, {SelectionAPIVersion, "b.block.b", []ScalarParameter{}}}
			for i := range catalogs {
				if catalogs[i].Provider == "b" {
					switch kind {
					case "contract":
						catalogs[i].Exports[0].Requires[0].ContractDigest = exportDigest('f')
					case "range":
						catalogs[i].Exports[0].Requires[0].CompatibleRange = ">=2.0.0 <3.0.0"
					case "bindings":
						catalogs[i].Exports[0].Parameters = []ScalarParameter{{Name: "flag", Value: json.RawMessage(`true`)}}
						requests[1].Bindings = catalogs[i].Exports[0].Parameters
					}
				}
				if kind == "cycle" && catalogs[i].Provider == "leaf" {
					catalogs[i].Exports[0].Requires = []ExportRequirement{{Selector: "middle.block.middle", ContractDigest: catalogs[i].ContractDigest, CompatibleRange: "*"}}
				}
				if kind == "missing" && catalogs[i].Provider == "leaf" {
					catalogs[i].Exports = []ExportEntry{}
				}
			}
			for _, order := range [][]Selection{requests, {requests[1], requests[0]}} {
				out, err := ResolveSelections(order, sources, catalogs)
				if err == nil || !reflect.DeepEqual(out, ExportGraph{}) {
					t.Fatalf("deep cached guard bypass: %+v %v", out, err)
				}
			}
		})
	}
}

func TestStageABatchCachedDepthGuard(t *testing.T) {
	c := catalogFixture()
	c.Exports = []ExportEntry{}
	children := map[string]string{"a": "middle", "b": "hop000", "middle": "leaf", "leaf": "tail"}
	for i := 0; i < 125; i++ {
		name := fmt.Sprintf("hop%03d", i)
		next := "middle"
		if i < 124 {
			next = fmt.Sprintf("hop%03d", i+1)
		}
		children[name] = next
	}
	names := []string{"a", "b", "middle", "leaf", "tail"}
	for i := 0; i < 125; i++ {
		names = append(names, fmt.Sprintf("hop%03d", i))
	}
	for _, name := range names {
		entry := ExportEntry{ID: name, Domain: "block", Name: name, Version: "1.0.0", ContentDigest: exportDigest('5'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('6'), Requires: []ExportRequirement{}}
		if child := children[name]; child != "" {
			entry.Requires = []ExportRequirement{{Selector: "base.block." + child, ContractDigest: c.ContractDigest, CompatibleRange: "*"}}
		}
		c.Exports = append(c.Exports, entry)
	}
	sort.Slice(c.Exports, func(i, j int) bool { return eKey(c.Exports[i]) < eKey(c.Exports[j]) })
	sources := bindCatalog(t, &c)
	a := Selection{SelectionAPIVersion, "base.block.a", []ScalarParameter{}}
	b := Selection{SelectionAPIVersion, "base.block.b", []ScalarParameter{}}
	if _, err := ResolveSelection(a, sources, []Catalog{c}); err != nil {
		t.Fatal(err)
	}
	for _, requests := range [][]Selection{{a, b}, {b, a}} {
		out, err := ResolveSelections(requests, sources, []Catalog{c})
		if err == nil || !strings.Contains(err.Error(), "dependency depth exceeded") || !reflect.DeepEqual(out, ExportGraph{}) {
			t.Fatalf("cached subtree bypassed depth refusal: %+v %v", out, err)
		}
	}
}

func TestStageABatchProvenanceBound(t *testing.T) {
	pins := []deps.PinnedSource{}
	for level := 0; level < 12; level++ {
		for side := 0; side < 2; side++ {
			alias := fmt.Sprintf("n%02d%c", level, 'a'+side)
			pins = append(pins, deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: alias, Origin: "https://example.test/" + alias, TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat("a", 40), TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: exportDigest('3'), EvidenceDigest: exportDigest('4'), Parameters: []deps.Parameter{}, Dependencies: []string{}})
		}
	}
	sources, err := deps.BuildSourceGraph(pins)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, node := range sources.Nodes {
		keys[node.Identity.ProviderID] = node.Key
	}
	catalogs := []Catalog{}
	for level := 0; level < 12; level++ {
		for side := 0; side < 2; side++ {
			alias := fmt.Sprintf("n%02d%c", level, 'a'+side)
			entry := ExportEntry{ID: "entry", Domain: "block", Name: "entry", Version: "1.0.0", ContentDigest: exportDigest('5'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('6'), Requires: []ExportRequirement{}}
			if level < 11 {
				for child := 0; child < 2; child++ {
					entry.Requires = append(entry.Requires, ExportRequirement{Selector: fmt.Sprintf("n%02d%c.block.entry", level+1, 'a'+child), ContractDigest: exportDigest('3'), CompatibleRange: "*"})
				}
			}
			catalogs = append(catalogs, Catalog{APIVersion: CatalogAPIVersion, Provider: alias, Source: keys[alias], ContractDigest: exportDigest('3'), Exports: []ExportEntry{entry}})
		}
	}
	a := Selection{SelectionAPIVersion, "n00a.block.entry", []ScalarParameter{}}
	b := Selection{SelectionAPIVersion, "n00b.block.entry", []ScalarParameter{}}
	within, err := ResolveSelections([]Selection{a}, sources, catalogs)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, record := range within.Selected {
		count += len(record.Chains)
	}
	if count != 4095 {
		t.Fatalf("within-bound closure lost paths: %d", count)
	}
	for _, requests := range [][]Selection{{a, b}, {b, a}} {
		out, err := ResolveSelections(requests, sources, catalogs)
		if err == nil || !strings.Contains(err.Error(), "batch provenance paths exceeded") || !reflect.DeepEqual(out, ExportGraph{}) {
			t.Fatalf("excess paths not bounded: %+v %v", out, err)
		}
	}
}

func TestStageABatchRequiredClosure(t *testing.T) {
	c, sources := batchCatalogFixture(t)
	selections := []Selection{{SelectionAPIVersion, "base.skill.skill", []ScalarParameter{}}, {SelectionAPIVersion, "base.approach.approach", []ScalarParameter{}}}
	g, err := ResolveSelections(selections, sources, []Catalog{c})
	if err != nil || len(g.Selected) != 3 || len(g.Edges) != 2 || g.Selected[0].ID != "floor" {
		t.Fatalf("required closure: %+v %v", g, err)
	}
	if len(g.Selected[0].Chains) != 2 {
		t.Fatalf("lost shared provenance: %+v", g.Selected[0])
	}
	reverse, err := ResolveSelections([]Selection{selections[1], selections[0]}, sources, []Catalog{c})
	if err != nil || !reflect.DeepEqual(g, reverse) {
		t.Fatalf("batch permutation changed result: %+v %v", reverse, err)
	}
	for _, selection := range selections {
		single, err := ResolveSelection(selection, sources, []Catalog{c})
		if err != nil {
			t.Fatal(err)
		}
		batch, err := ResolveSelections([]Selection{selection}, sources, []Catalog{c})
		if err != nil || !reflect.DeepEqual(single, batch) {
			t.Fatalf("single contract differs %v", err)
		}
	}
	for name, requests := range map[string][]Selection{
		"empty": {}, "duplicate": {selections[0], selections[0]},
		"unknown-provider": {{SelectionAPIVersion, "unknown.skill.skill", []ScalarParameter{}}},
		"unknown-export":   {{SelectionAPIVersion, "base.skill.absent", []ScalarParameter{}}},
		"invalid-domain":   {{SelectionAPIVersion, "base.skills.skill", []ScalarParameter{}}},
		"missing-bindings": {{APIVersion: SelectionAPIVersion, Selector: "base.skill.skill"}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := ResolveSelections(requests, sources, []Catalog{c})
			if err == nil || !reflect.DeepEqual(out, ExportGraph{}) {
				t.Fatalf("invalid batch returned %v %v", out, err)
			}
		})
	}
	for _, kind := range []string{"missing", "version", "contract"} {
		t.Run(kind, func(t *testing.T) {
			broken := c
			broken.Exports = append([]ExportEntry(nil), c.Exports...)
			if kind == "missing" {
				broken.Exports = broken.Exports[1:]
			} else if kind == "version" {
				broken.Exports[0].Version = "2.0.0"
			} else {
				for i := 1; i < len(broken.Exports); i++ {
					broken.Exports[i].Requires = []ExportRequirement{{Selector: "base.block.floor", ContractDigest: exportDigest('f'), CompatibleRange: "*"}}
				}
			}
			if _, err := ResolveSelections(selections, sources, []Catalog{broken}); err == nil {
				t.Fatal("required floor mismatch accepted")
			}
		})
	}
}

func TestStageASingleSelectionDigest(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	sources := bindCatalog(t, &c)
	g, err := ResolveSelection(Selection{SelectionAPIVersion, "base.block.header", []ScalarParameter{}}, sources, []Catalog{c})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	// Captured independently from the unchanged cbb6e19 engine, including all
	// selected pins, provenance chains and the graph digest.
	if g.Digest != "sha256:c14ae064a9783b22d07d086f2b99866ec594428b93091cdcce15b1b3d939cbe5" || digestBytes(wire) != "sha256:b0a3dc955e2efcf2f33c6a5cee1dd11e8e8174bf5db22bbf03ceba9d52b367ef" {
		t.Fatalf("legacy single wire changed: %s", wire)
	}
}

func TestStageABatchBindingConflict(t *testing.T) {
	c, sources := batchCatalogFixture(t)
	for i := range c.Exports {
		if c.Exports[i].Domain == "skill" {
			c.Exports[i].Parameters = []ScalarParameter{{Name: "flag", Value: json.RawMessage(`true`)}}
		}
	}
	requests := []Selection{{SelectionAPIVersion, "base.skill.skill", []ScalarParameter{{Name: "flag", Value: json.RawMessage(`true`)}}}, {SelectionAPIVersion, "base.approach.approach", []ScalarParameter{}}}
	for _, request := range requests {
		if _, err := ResolveSelection(request, sources, []Catalog{c}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ResolveSelections(requests, sources, []Catalog{c}); err == nil || !strings.Contains(err.Error(), "incompatible shared prerequisite") {
		t.Fatalf("bindings overwritten: %v", err)
	}
	// An entry explicitly requested with wrong bindings must still refuse when
	// it was already visited as another selection's prerequisite.
	requests = []Selection{{SelectionAPIVersion, "base.approach.approach", []ScalarParameter{}}, {SelectionAPIVersion, "base.block.floor", []ScalarParameter{{Name: "flag", Value: json.RawMessage(`true`)}}}}
	if _, err := ResolveSelections(requests, sources, []Catalog{c}); err == nil {
		t.Fatal("visited prerequisite bypassed root bindings")
	}
}

func TestResolveSelectionProviderIsolationAndExportIDOrder(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	graph := bindCatalog(t, &c)
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}
	g, err := ResolveSelection(sel, graph, []Catalog{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Selected) != 1 || g.Selected[0].ID != "entry-a" {
		t.Fatalf("selected=%+v", g.Selected)
	}
	bad := sel
	bad.Selector = "other.block.header"
	if _, err := ResolveSelection(bad, graph, []Catalog{c}); err == nil {
		t.Fatal("cross-provider fallback accepted")
	}
	bad = sel
	bad.Bindings = []ScalarParameter{{Name: "flag", Value: json.RawMessage(`true`)}}
	if _, err := ResolveSelection(bad, graph, []Catalog{c}); err == nil {
		t.Fatal("parameter mismatch accepted")
	}
}

func TestResolveSelectionRejectsAmbiguousProviderLocalIDs(t *testing.T) {
	c := catalogFixture()
	graph := bindCatalog(t, &c)
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}
	if _, err := ResolveSelection(sel, graph, []Catalog{c}); err == nil {
		t.Fatal("ambiguous provider-local IDs accepted")
	}
}

func TestResolveSelectionBindsActualSourceAndRequirementContract(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	graph := bindCatalog(t, &c)
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}
	for name, mutate := range map[string]func(*Catalog){
		"forged source":   func(v *Catalog) { v.Source = exportDigest('f') },
		"forged contract": func(v *Catalog) { v.ContractDigest = exportDigest('f') },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mutate(&bad)
			if _, err := ResolveSelection(sel, graph, []Catalog{bad}); err == nil {
				t.Fatal("unbound catalog accepted")
			}
		})
	}
	c.Exports[0].Requires = []ExportRequirement{{Selector: "base.block.header", ContractDigest: exportDigest('f'), CompatibleRange: "*"}}
	if _, err := ResolveSelection(sel, graph, []Catalog{c}); err == nil {
		t.Fatal("requirement contract mismatch accepted")
	}
}

func TestOrderReadySelectKeysUsesFinalExportID(t *testing.T) {
	c := catalogFixture()
	items := []selectKey{
		{catalog: c, entry: c.Exports[1], depth: 0},
		{catalog: c, entry: c.Exports[0], depth: 0},
	}
	ordered, err := orderReadySelectKeys(items, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{ordered[0].entry.ID, ordered[1].entry.ID}; got[0] != "entry-a" || got[1] != "entry-z" {
		t.Fatalf("ready order=%v", got)
	}
}

func TestResolveSelectionKahnPrerequisiteOrderIsPermutationStable(t *testing.T) {
	c := catalogFixture()
	c.Exports = []ExportEntry{
		{ID: "consumer", Domain: "block", Name: "consumer", Version: "1.0.0", ContentDigest: exportDigest('c'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('d'), Requires: []ExportRequirement{{Selector: "base.block.header", ContractDigest: c.ContractDigest, CompatibleRange: "*"}}},
		{ID: "entry-a", Domain: "block", Name: "header", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{}},
	}
	// Catalog order is part of the strict wire, while input catalog order is
	// intentionally permuted across resolver calls.
	sort.Slice(c.Exports, func(i, j int) bool { return eKey(c.Exports[i]) < eKey(c.Exports[j]) })
	graph := bindCatalog(t, &c)
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.consumer", Bindings: []ScalarParameter{}}
	g1, err := ResolveSelection(sel, graph, []Catalog{c})
	if err != nil {
		t.Fatal(err)
	}
	reversed := append([]ExportEntry(nil), c.Exports...)
	sort.Slice(reversed, func(i, j int) bool { return eKey(reversed[i]) > eKey(reversed[j]) })
	c2 := c
	c2.Exports = reversed
	// A noncanonical catalog is rejected before resolution, preserving wire
	// validation; the production ordering is exercised by the first call and
	// the helper vector above.
	if _, err := ResolveSelection(sel, graph, []Catalog{c2}); err == nil {
		t.Fatal("noncanonical catalog accepted")
	}
	if len(g1.Selected) != 2 || g1.Selected[0].Name != "header" || g1.Selected[1].Name != "consumer" {
		t.Fatalf("kahn order=%+v", g1.Selected)
	}
}

func TestResolveSelectionBoundMultiProviderDAGIsPermutationStable(t *testing.T) {
	baseContract, depContract := exportDigest('b'), exportDigest('c')
	base := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "base", ProviderID: "base", Origin: "https://example.test/base", TemplatePath: ".", RequestedRef: "refs/tags/v1", CommitAlgorithm: "sha1", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: baseContract, EvidenceDigest: exportDigest('3'), Parameters: []deps.Parameter{}, Dependencies: []string{}}
	dep := base
	dep.Alias = "dep"
	dep.ProviderID = "dep"
	dep.Origin = "https://example.test/dep"
	dep.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dep.ContractDigest = depContract
	graph, err := deps.BuildSourceGraph([]deps.PinnedSource{dep, base})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, n := range graph.Nodes {
		keys[n.Identity.ProviderID] = n.Key
	}
	depCatalog := Catalog{APIVersion: CatalogAPIVersion, Provider: "dep", Source: keys["dep"], ContractDigest: depContract, Exports: []ExportEntry{{ID: "header", Domain: "block", Name: "header", Version: "1.0.0", ContentDigest: exportDigest('d'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('e'), Requires: []ExportRequirement{}}}}
	baseCatalog := Catalog{APIVersion: CatalogAPIVersion, Provider: "base", Source: keys["base"], ContractDigest: baseContract, Exports: []ExportEntry{{ID: "consumer", Domain: "block", Name: "consumer", Version: "1.0.0", ContentDigest: exportDigest('f'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('a'), Requires: []ExportRequirement{{Selector: "dep.block.header", ContractDigest: depContract, CompatibleRange: "*"}}}}}
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.consumer", Bindings: []ScalarParameter{}}
	one, err := ResolveSelection(sel, graph, []Catalog{baseCatalog, depCatalog})
	if err != nil {
		t.Fatal(err)
	}
	two, err := ResolveSelection(sel, graph, []Catalog{depCatalog, baseCatalog})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one, two) || len(one.Selected) != 2 || one.Selected[0].Provider != "dep" || one.Selected[1].Provider != "base" {
		t.Fatalf("permuted DAG=%+v / %+v", one, two)
	}
	if got := one.Selected[0].Chains; len(got) != 1 || !reflect.DeepEqual(got[0], []string{"base", "dep"}) {
		t.Fatalf("dependency chains=%v", got)
	}
}

func TestResolveSelectionChecksRangeAndContractOnEveryDiamondEdge(t *testing.T) {
	contracts := map[string]string{"base": exportDigest('a'), "left": exportDigest('b'), "right": exportDigest('c'), "shared": exportDigest('d')}
	pins := make([]deps.PinnedSource, 0, len(contracts))
	for _, alias := range []string{"base", "left", "right", "shared"} {
		commitByte := map[string]byte{"base": 'a', "left": 'b', "right": 'c', "shared": 'd'}[alias]
		p := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: alias, ProviderID: alias, Origin: "https://example.test/" + alias, TemplatePath: ".", RequestedRef: "refs/tags/v1", CommitAlgorithm: "sha1", Commit: strings.Repeat(string(commitByte), 40), TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: contracts[alias], EvidenceDigest: exportDigest('3'), Parameters: []deps.Parameter{}, Dependencies: []string{}}
		pins = append(pins, p)
	}
	sources, err := deps.BuildSourceGraph(pins)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, node := range sources.Nodes {
		keys[node.Identity.ProviderID] = node.Key
	}
	shared := Catalog{APIVersion: CatalogAPIVersion, Provider: "shared", Source: keys["shared"], ContractDigest: contracts["shared"], Exports: []ExportEntry{{ID: "header", Domain: "block", Name: "header", Version: "1.2.3+build.7", ContentDigest: exportDigest('4'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('5'), Requires: []ExportRequirement{}}}}
	left := Catalog{APIVersion: CatalogAPIVersion, Provider: "left", Source: keys["left"], ContractDigest: contracts["left"], Exports: []ExportEntry{{ID: "left", Domain: "block", Name: "left", Version: "1.0.0", ContentDigest: exportDigest('6'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('7'), Requires: []ExportRequirement{{Selector: "shared.block.header", ContractDigest: contracts["shared"], CompatibleRange: ">=1.0.0 <2.0.0"}}}}}
	right := Catalog{APIVersion: CatalogAPIVersion, Provider: "right", Source: keys["right"], ContractDigest: contracts["right"], Exports: []ExportEntry{{ID: "right", Domain: "block", Name: "right", Version: "1.0.0", ContentDigest: exportDigest('8'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('9'), Requires: []ExportRequirement{{Selector: "shared.block.header", ContractDigest: contracts["shared"], CompatibleRange: "=1.2.3+build.7"}}}}}
	base := Catalog{APIVersion: CatalogAPIVersion, Provider: "base", Source: keys["base"], ContractDigest: contracts["base"], Exports: []ExportEntry{{ID: "consumer", Domain: "block", Name: "consumer", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{{Selector: "left.block.left", ContractDigest: contracts["left"], CompatibleRange: "*"}, {Selector: "right.block.right", ContractDigest: contracts["right"], CompatibleRange: "*"}}}}}
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.consumer", Bindings: []ScalarParameter{}}
	got, err := ResolveSelection(sel, sources, []Catalog{right, shared, base, left})
	if err != nil || len(got.Selected) != 4 || got.Selected[0].Provider != "shared" {
		t.Fatalf("valid diamond=%+v err=%v", got, err)
	}
	for name, mutate := range map[string]func(){
		"unsatisfied range on second shared edge": func() { right.Exports[0].Requires[0].CompatibleRange = ">=2.0.0" },
		"unsupported range on second shared edge": func() { right.Exports[0].Requires[0].CompatibleRange = "^1.2.3" },
		"wrong contract on second shared edge":    func() { right.Exports[0].Requires[0].ContractDigest = exportDigest('f') },
	} {
		t.Run(name, func(t *testing.T) {
			badRight := right
			badRight.Exports = append([]ExportEntry(nil), right.Exports...)
			badRight.Exports[0].Requires = append([]ExportRequirement(nil), right.Exports[0].Requires...)
			right = badRight
			mutate()
			_, err := ResolveSelection(sel, sources, []Catalog{base, left, right, shared})
			if err == nil || !strings.Contains(err.Error(), "EXPORT_FACT_MISMATCH") {
				t.Fatalf("diamond mismatch bypassed: %v", err)
			}
			right = Catalog{APIVersion: CatalogAPIVersion, Provider: "right", Source: keys["right"], ContractDigest: contracts["right"], Exports: []ExportEntry{{ID: "right", Domain: "block", Name: "right", Version: "1.0.0", ContentDigest: exportDigest('8'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('9'), Requires: []ExportRequirement{{Selector: "shared.block.header", ContractDigest: contracts["shared"], CompatibleRange: "=1.2.3+build.7"}}}}}
		})
	}
}

func TestResolveSelectionRequiresCycleAndDeterminism(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	c.Exports[0].Requires = []ExportRequirement{{Selector: "base.block.header", ContractDigest: c.ContractDigest, CompatibleRange: "*"}}
	c.Exports[0].ID = "entry-a"
	graph := bindCatalog(t, &c)
	if _, err := ResolveSelection(Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}, graph, []Catalog{c}); err == nil {
		t.Fatal("export cycle accepted")
	}
	entries := append([]ExportEntry(nil), catalogFixture().Exports...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
	if entries[0].ID != "entry-z" {
		t.Fatal("fixture ordering changed")
	}
}
