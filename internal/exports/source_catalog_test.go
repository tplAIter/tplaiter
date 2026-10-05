package exports

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

var exportSourceFixture = flag.String("export-source-fixture", "", "reviewed immutable public source data directory")

func sourceDataFixture(t *testing.T) SourceCatalogInput {
	t.Helper()
	content := []byte("Public task context.\n")
	tool := []byte("Readonly file preview; no execution.\n")
	raw := materialPayload("notes", "docs/notes.md", "context/notes.md", content, "100644")
	c := catalogFixture()
	c.Exports = []ExportEntry{{ID: "notes", Domain: "block", Name: "notes", Version: "1.0.0", ContentDigest: digestBytes(raw), Parameters: []ScalarParameter{}, Requires: []ExportRequirement{}, ToolDigest: digestBytes(tool)}}
	entries, err := json.Marshal(c.Exports)
	if err != nil {
		t.Fatal(err)
	}
	p := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "neutral", ProviderID: "generic-provider", Origin: "https://example.test/provider", TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat("a", 40), TreeDigest: exportDigest('1'), ContentDigest: exportDigest('2'), ContractDigest: c.ContractDigest, EvidenceDigest: exportDigest('3'), Parameters: []deps.Parameter{}, Dependencies: []string{}}
	return SourceCatalogInput{Pins: []deps.PinnedSource{p}, Alias: p.Alias, Data: CatalogData{Entries: entries, Tool: tool, Payloads: []SourcePayload{{"notes", raw}}, Blobs: []MaterialBlob{{"docs/notes.md", "100644", content}}}}
}

func TestSourceCatalogStrictData(t *testing.T) {
	in := sourceDataFixture(t)
	out, err := BuildSourceCatalog(in)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(out.Catalog)
	if _, err := ParseCatalog(wire); err != nil {
		t.Fatal(err)
	}
	selection := Selection{APIVersion: SelectionAPIVersion, Selector: "neutral.block.notes", Bindings: []ScalarParameter{}}
	g, err := ResolveSelections([]Selection{selection}, out.Sources, []Catalog{out.Catalog})
	if err != nil || len(g.Selected) != 1 || g.Selected[0].Source != out.Sources.Nodes[0].Key {
		t.Fatalf("selection %v %v", g, err)
	}
	in.Data.Payloads[0].Raw[0] = '!'
	in.Data.Blobs[0].Content[0] = '!'
	if out.Payloads[0].Raw[0] != '{' || out.Blobs[0].Content[0] != 'P' {
		t.Fatal("output aliases mutable input bytes")
	}
	for name, mutate := range map[string]func(*SourceCatalogInput){
		"missing-alias": func(in *SourceCatalogInput) { in.Alias = "missing" },
		"invalid-pin":   func(in *SourceCatalogInput) { in.Pins[0].Commit = "bad" },
		"missing-entry-field": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `,"requires":[]`, "", 1))
		},
		"duplicate-entry-key": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"id":"notes"`, `"id":"notes","id":"notes"`, 1))
		},
		"nonexact-entry-key": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"id":`, `"ID":`, 1))
		},
		"nonexact-requires-key": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"requires":[]`, `"requires":[{"Selector":"neutral.block.notes","contractDigest":"`+in.Pins[0].ContractDigest+`","compatibleRange":"*"}]`, 1))
		},
		"nonexact-parameter-key": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"parameters":[]`, `"parameters":[{"Name":"flag","value":true}]`, 1))
		},
		"fractional-parameter": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"parameters":[]`, `"parameters":[{"name":"count","value":1.0}]`, 1))
		},
		"unknown-entry-key": func(in *SourceCatalogInput) {
			in.Data.Entries = []byte(strings.Replace(string(in.Data.Entries), `"id":"notes"`, `"id":"notes","unknown":true`, 1))
		},
		"duplicate-entry-id": func(in *SourceCatalogInput) {
			var es []ExportEntry
			json.Unmarshal(in.Data.Entries, &es)
			es = append(es, es[0])
			in.Data.Entries, _ = json.Marshal(es)
		},
		"missing-payload":   func(in *SourceCatalogInput) { in.Data.Payloads = []SourcePayload{} },
		"duplicate-payload": func(in *SourceCatalogInput) { in.Data.Payloads = append(in.Data.Payloads, in.Data.Payloads[0]) },
		"malformed-duplicate": func(in *SourceCatalogInput) {
			in.Data.Payloads = append(in.Data.Payloads, SourcePayload{"notes", []byte(`{"exportID":"notes"}`)})
		},
		"payload-digest": func(in *SourceCatalogInput) { in.Data.Payloads[0].Raw = append(in.Data.Payloads[0].Raw, '\n') },
		"tool-digest":    func(in *SourceCatalogInput) { in.Data.Tool = []byte("changed") },
		"content-digest": func(in *SourceCatalogInput) { in.Data.Blobs[0].Content = []byte("changed") },
		"mode":           func(in *SourceCatalogInput) { in.Data.Blobs[0].Mode = "100755" },
		"duplicate-blob": func(in *SourceCatalogInput) { in.Data.Blobs = append(in.Data.Blobs, in.Data.Blobs[0]) },
		"extra-blob": func(in *SourceCatalogInput) {
			in.Data.Blobs = append(in.Data.Blobs, MaterialBlob{"docs/unused", "100644", []byte("unused")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := sourceDataFixture(t)
			mutate(&in)
			out, err := BuildSourceCatalog(in)
			if err == nil || !reflect.DeepEqual(out, SourceCatalog{}) {
				t.Fatalf("invalid data accepted: %+v %v", out, err)
			}
		})
	}
}

func TestSourceCatalogMultiSourceClosure(t *testing.T) {
	in := sourceDataFixture(t)
	other := in.Pins[0]
	other.Alias = "other"
	other.ProviderID = "other-provider"
	other.Origin = "https://example.test/other"
	in.Pins[0].Dependencies = []string{"other"}
	in.Pins = append(in.Pins, other)
	var entries []ExportEntry
	if err := json.Unmarshal(in.Data.Entries, &entries); err != nil {
		t.Fatal(err)
	}
	entries[0].Requires = []ExportRequirement{{Selector: "other.block.notes", ContractDigest: other.ContractDigest, CompatibleRange: ">=1.0.0 <2.0.0"}}
	in.Data.Entries, _ = json.Marshal(entries)
	root, err := BuildSourceCatalog(in)
	if err != nil {
		t.Fatal(err)
	}
	depInput := sourceDataFixture(t)
	depInput.Pins = in.Pins
	depInput.Alias = "other"
	dep, err := BuildSourceCatalog(depInput)
	if err != nil {
		t.Fatal(err)
	}
	requests := []Selection{{SelectionAPIVersion, "neutral.block.notes", []ScalarParameter{}}, {SelectionAPIVersion, "other.block.notes", []ScalarParameter{}}}
	g, err := ResolveSelections(requests, root.Sources, []Catalog{dep.Catalog, root.Catalog})
	if err != nil || len(g.Selected) != 2 || len(g.Edges) != 1 || g.Selected[0].Provider != "other-provider" {
		t.Fatalf("multi-source closure: %+v %v", g, err)
	}
	if _, err := ResolveSelections(requests, root.Sources, []Catalog{root.Catalog}); err == nil {
		t.Fatal("missing dependency catalog accepted")
	}
}

// The opt-in directory is a reviewed immutable public source freeze, not code
// loaded from that provider. Normal builds need neither the fixture nor overlays.
func TestSourceCatalogFrozenTemplateData(t *testing.T) {
	root := *exportSourceFixture
	if root == "" {
		t.Skip("reviewed public source fixture not supplied")
	}
	read := func(path string) []byte {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	data := CatalogData{Entries: read("catalog/entries.json"), Tool: read("catalog/tool-contract.md"), Payloads: []SourcePayload{}, Blobs: []MaterialBlob{}}
	var entries []ExportEntry
	if err := json.Unmarshal(data.Entries, &entries); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, entry := range entries {
		raw := read("catalog/payloads/" + entry.ID + ".json")
		data.Payloads = append(data.Payloads, SourcePayload{entry.ID, raw})
		p, err := ParseExportPayload(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range p.Files {
			if !paths[f.SourcePath] {
				paths[f.SourcePath] = true
				data.Blobs = append(data.Blobs, MaterialBlob{f.SourcePath, f.Mode, read(f.SourcePath)})
			}
		}
	}
	in := sourceDataFixture(t)
	in.Pins[0].Alias = "base"
	in.Alias = "base"
	in.Pins[0].ProviderID = "template-base"
	// This pin is deliberately synthetic content-validation input. Authentication
	// of eventual published source is an admission requirement outside stage A.
	in.Pins[0].ContractDigest = "sha256:6b6e9e42ed81c1c6f520dbbbbd9c4ab2ba0100a7a3089467cff52b5f800cf075"
	in.Data = data
	out, err := BuildSourceCatalog(in)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ResolveSelections([]Selection{{SelectionAPIVersion, "base.skill.context-selection", []ScalarParameter{}}, {SelectionAPIVersion, "base.approach.transparent-overrides", []ScalarParameter{}}}, out.Sources, []Catalog{out.Catalog})
	if err != nil || len(g.Selected) != 4 || len(g.Edges) != 2 {
		t.Fatalf("frozen closure %+v %v", g, err)
	}
	payloads := map[string][]byte{}
	blobs := map[string]MaterialBlob{}
	for _, p := range out.Payloads {
		payloads[p.ExportID] = p.Raw
	}
	for _, b := range out.Blobs {
		blobs[b.Path] = b
	}
	m := closedMaterialInput()
	for i, s := range g.Selected {
		raw := payloads[s.ID]
		p, _ := ParseExportPayload(raw)
		src := MaterialSource{Selected: s, Payload: raw, Blobs: []MaterialBlob{}}
		for j, f := range p.Files {
			src.Blobs = append(src.Blobs, blobs[f.SourcePath])
			m.Current = append(m.Current, FileState{Path: f.TargetPath})
			m.Operations = append(m.Operations, MaterialOperation{Kind: "add", Path: f.TargetPath, AfterOwner: MaterialOwner{Provider: s.Provider, RuleID: s.ID, ExportID: s.ID}, SourceIndex: i, EntryIndex: j})
		}
		m.Sources = append(m.Sources, src)
	}
	preview, err := Materialize(m)
	if err != nil || len(preview.Images) != 4 || len(preview.Conflicts) != 0 {
		t.Fatalf("frozen batch preview %+v %v", preview, err)
	}
	for _, image := range preview.Images {
		found := false
		for _, b := range data.Blobs {
			if digestBytes(b.Content) == image.After.ContentSHA256 && string(b.Content) == string(image.After.Content) {
				found = true
			}
		}
		if !found {
			t.Fatalf("unbound image %s", image.Path)
		}
	}
	ids := []string{}
	for _, s := range g.Selected {
		ids = append(ids, s.ID)
	}
	sort.Strings(ids)
	t.Logf("actual data-only compiled selection/materialization IDs=%v graph=%s", ids, g.Digest)
}
