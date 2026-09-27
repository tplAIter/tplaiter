package exports

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

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
