package exports

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

func exportDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
func catalogFixture() Catalog {
	return Catalog{APIVersion: CatalogAPIVersion, Provider: "base", Source: exportDigest('a'), ContractDigest: exportDigest('b'), Exports: []ExportEntry{
		{ID: "entry-a", Domain: "block", Name: "header", Version: "1.0.0", ContentDigest: exportDigest('c'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('d'), Requires: []ExportRequirement{}},
		{ID: "entry-z", Domain: "block", Name: "header", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{}},
	}}
}

func bindCatalog(t *testing.T, c *Catalog) *deps.SourceGraph {
	t.Helper()
	p := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "base", ProviderID: c.Provider, Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: "refs/tags/v1", CommitAlgorithm: "sha1", Commit: strings.Repeat("a", 40), TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: c.ContractDigest, EvidenceDigest: exportDigest('3'), Parameters: []deps.Parameter{}, Dependencies: []string{}}
	g, err := deps.BuildSourceGraph([]deps.PinnedSource{p})
	if err != nil {
		t.Fatal(err)
	}
	c.Source = g.Nodes[0].Key
	return g
}

func TestCatalogStrictWireAndCanonicalOrdering(t *testing.T) {
	c := catalogFixture()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCatalog(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown": func(b []byte) []byte { return []byte(strings.Replace(string(b), "}", ",\"extra\":1}", 1)) },
		"duplicate": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), "{\"apiVersion\":", "{\"apiVersion\":\"x\",\"apiVersion\":", 1))
		},
		"bad-digest": func(b []byte) []byte { return []byte(strings.Replace(string(b), "sha256:", "sha257:", 1)) },
	} {
		if _, err := ParseCatalog(mutate(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c.Exports[0], c.Exports[1] = c.Exports[1], c.Exports[0]
	if err := c.Validate(); err == nil {
		t.Fatal("shuffled catalog accepted")
	}
}

func TestCatalogAndSelectionRejectRawNonIntegerScalarLexemes(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	c.Exports[0].Parameters = []ScalarParameter{{Name: "count", Value: json.RawMessage(`0`)}}
	catalogRaw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{{Name: "count", Value: json.RawMessage(`0`)}}}
	selectionRaw, err := json.Marshal(sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		lexeme string
		valid  bool
	}{
		{"0", true}, {"-1", true}, {"9007199254740991", true}, {"-9007199254740991", true},
		{"1.0", false}, {"1e0", false}, {"-0", false}, {"9007199254740992", false}, {"-9007199254740992", false},
	} {
		t.Run(tc.lexeme, func(t *testing.T) {
			catalogCandidate := []byte(strings.Replace(string(catalogRaw), `"value":0`, `"value":`+tc.lexeme, 1))
			selectionCandidate := []byte(strings.Replace(string(selectionRaw), `"value":0`, `"value":`+tc.lexeme, 1))
			_, catalogErr := ParseCatalog(catalogCandidate)
			_, selectionErr := ParseSelection(selectionCandidate)
			if (catalogErr == nil) != tc.valid || (selectionErr == nil) != tc.valid {
				t.Fatalf("lexeme %q valid=%v catalog=%v selection=%v", tc.lexeme, tc.valid, catalogErr, selectionErr)
			}
		})
	}
}

func TestCatalogUsesProviderTokenAndExportNameAliasGrammar(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	c.Provider = "provider.base"
	graph := bindCatalog(t, &c)
	if _, err := ResolveSelection(Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}, graph, []Catalog{c}); err != nil {
		t.Fatalf("dotted provider did not bind its source graph node: %v", err)
	}
	c.Exports[0].Name = "header.dot"
	if err := c.Validate(); err == nil {
		t.Fatal("dotted export name accepted")
	}
}

func TestCanonicalExportIdentityVectorsAndTamper(t *testing.T) {
	c := catalogFixture()
	c.Exports = c.Exports[:1]
	graph := bindCatalog(t, &c)
	entryID, err := CatalogEntryIdentity(c, c.Exports[0])
	if err != nil {
		t.Fatal(err)
	}
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}
	bindID, err := SelectionBindingsIdentity(sel)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ResolveSelection(sel, graph, []Catalog{c})
	if err != nil {
		t.Fatal(err)
	}
	selectedID, err := SelectedExportIdentity(g.Selected[0])
	if err != nil {
		t.Fatal(err)
	}
	if entryID != "sha256:332b4964ec6a66d72037802dcdfdc5ad273a016daf660b9364aec6c0f49ed506" ||
		bindID != "sha256:0aa94bbaf8dc62069e73dd20d661753deea3941a51ffb0c6da2261606d3090d7" ||
		selectedID != "sha256:9157f648863585f2add056a39b1206e2abbe1f8ae8c1fd0a47ad6c35a39376fb" ||
		g.Digest != "sha256:c14ae064a9783b22d07d086f2b99866ec594428b93091cdcce15b1b3d939cbe5" {
		t.Fatalf("unexpected identity vector entry=%s bindings=%s selected=%s graph=%s", entryID, bindID, selectedID, g.Digest)
	}

	tampered := c.Exports[0]
	tampered.ContentDigest = exportDigest('e')
	if a, _ := CatalogEntryIdentity(c, tampered); a == entryID {
		t.Fatal("entry identity ignored content digest")
	}
	tamperedSelected := g.Selected[0]
	tamperedSelected.ToolDigest = exportDigest('e')
	if a, _ := SelectedExportIdentity(tamperedSelected); a == selectedID {
		t.Fatal("selected identity ignored tool digest")
	}
	tamperedSelected = g.Selected[0]
	tamperedSelected.SourceParameterSHA256 = exportDigest('e')
	if a, _ := SelectedExportIdentity(tamperedSelected); a == selectedID {
		t.Fatal("selected identity ignored source parameter digest")
	}
	if a, _ := ExportGraphDigest(g.Selected, g.Edges); a != g.Digest {
		t.Fatal("graph digest is not replay-stable")
	}
	tamperedEdges := append([]ExportEdge(nil), g.Edges...)
	tamperedEdges = append(tamperedEdges, ExportEdge{Dependency: "base\x00block\x00other", Consumer: "base\x00block\x00header"})
	if a, _ := ExportGraphDigest(g.Selected, tamperedEdges); a == g.Digest {
		t.Fatal("graph identity ignored edge tamper")
	}
}

func TestCatalogUsesDomainRankAndRejectsDuplicateRequirementsAndBounds(t *testing.T) {
	c := catalogFixture()
	c.Exports = []ExportEntry{
		{ID: "approach", Domain: "approach", Name: "a", Version: "1.0.0", ContentDigest: exportDigest('c'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('d'), Requires: []ExportRequirement{}},
		{ID: "block", Domain: "block", Name: "z", Version: "1.0.0", ContentDigest: exportDigest('e'), Parameters: []ScalarParameter{}, ToolDigest: exportDigest('f'), Requires: []ExportRequirement{}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("lexical domain ordering accepted")
	}
	c.Exports[0], c.Exports[1] = c.Exports[1], c.Exports[0]
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Exports[0].Requires = []ExportRequirement{{Selector: "base.block.header", ContractDigest: c.ContractDigest, CompatibleRange: "*"}, {Selector: "base.block.header", ContractDigest: c.ContractDigest, CompatibleRange: "*"}}
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate requirement accepted")
	}
	if _, err := ParseCatalog(append([]byte(`{`), make([]byte, maxCatalogWireBytes)...)); err == nil {
		t.Fatal("oversize catalog accepted")
	}
	c = catalogFixture()
	c.Exports = c.Exports[:1]
	c.Exports[0].Version = "1.0.0\xff"
	if err := c.Validate(); err == nil {
		t.Fatal("non-UTF-8 version accepted")
	}
	c.Exports[0].Version = "1.0.0"
	c.Exports[0].Requires = []ExportRequirement{{Selector: "base.block.header", ContractDigest: c.ContractDigest, CompatibleRange: string([]byte{'*', 0xff})}}
	if err := c.Validate(); err == nil {
		t.Fatal("non-UTF-8 range accepted")
	}
}

func TestExportVersionChangesAllExportIdentities(t *testing.T) {
	base := catalogFixture()
	base.Exports = base.Exports[:1]
	graph := bindCatalog(t, &base)
	sel := Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}
	entry, err := CatalogEntryIdentity(base, base.Exports[0])
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveSelection(sel, graph, []Catalog{base})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := SelectedExportIdentity(resolved.Selected[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.1", "1.0.0+build.1"} {
		t.Run(version, func(t *testing.T) {
			changed := base
			changed.Exports = append([]ExportEntry(nil), base.Exports...)
			changed.Exports[0].Version = version
			changedEntry, err := CatalogEntryIdentity(changed, changed.Exports[0])
			if err != nil || changedEntry == entry {
				t.Fatalf("entry identity version=%q identity=%s err=%v", version, changedEntry, err)
			}
			changedGraph, err := ResolveSelection(sel, graph, []Catalog{changed})
			if err != nil {
				t.Fatal(err)
			}
			changedSelected, err := SelectedExportIdentity(changedGraph.Selected[0])
			if err != nil || changedSelected == selected || changedGraph.Digest == resolved.Digest {
				t.Fatalf("selected/graph identity version=%q selected=%s graph=%s err=%v", version, changedSelected, changedGraph.Digest, err)
			}
		})
	}
}

func TestCatalogAndSelectionTypedBounds(t *testing.T) {
	c := catalogFixture()
	c.Exports = make([]ExportEntry, 4097)
	if err := c.Validate(); err == nil {
		t.Fatal("typed catalog export bound accepted")
	}
	c = catalogFixture()
	c.Exports = c.Exports[:1]
	c.Exports[0].Requires = make([]ExportRequirement, maxExportRequires+1)
	if err := c.Validate(); err == nil {
		t.Fatal("typed requirement bound accepted")
	}
	if err := (Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: make([]ScalarParameter, 257)}).Validate(); err == nil {
		t.Fatal("typed selection binding bound accepted")
	}
	bound := catalogFixture()
	graph := bindCatalog(t, &bound)
	if _, err := ResolveSelection(Selection{APIVersion: SelectionAPIVersion, Selector: "base.block.header", Bindings: []ScalarParameter{}}, graph, make([]Catalog, maxResolverCatalogs+1)); err == nil {
		t.Fatal("resolver catalog bound accepted")
	}
}
