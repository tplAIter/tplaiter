package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/graphview"
)

func fixture(t *testing.T) (Catalog, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "knowledge", "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d, raw
}

func wire(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	s, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "knowledge.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func schemaCheck(s *jsonschema.Schema, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return s.Validate(v)
}

func TestWireAndPublicSchema(t *testing.T) {
	_, raw := fixture(t)
	s := schema(t)
	if err := schemaCheck(s, raw); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, code string
		mutate     func(map[string]any)
	}{
		{"unknown major", UnsupportedVersion, func(d map[string]any) { d["apiVersion"] = "tplaiter.dev/knowledge/v2"; d["futureMajorField"] = true }},
		{"missing protocol", Invalid, func(d map[string]any) { delete(d, "apiVersion") }},
		{"token window", Invalid, func(d map[string]any) { d["tokenWindow"] = 4096 }},
		{"org trust", Invalid, func(d map[string]any) { d["orgTrust"] = true }},
		{"missing pins", IncompletePin, func(d map[string]any) {
			delete(d["sources"].([]any)[0].(map[string]any)["pin"].(map[string]any), "evidenceDigest")
		}},
		{"missing proof", IncompletePin, func(d map[string]any) {
			delete(d["sources"].([]any)[0].(map[string]any)["anchor"].(map[string]any), "signatureCAS")
		}},
		{"empty pins", IncompletePin, func(d map[string]any) {
			d["sources"].([]any)[0].(map[string]any)["pin"].(map[string]any)["commit"] = ""
		}},
		{"null metadata", Invalid, func(d map[string]any) { d["items"].([]any)[0].(map[string]any)["quality"] = nil }},
		{"missing requires", Invalid, func(d map[string]any) { delete(d["items"].([]any)[0].(map[string]any), "requires") }},
		{"caller authenticated", Invalid, func(d map[string]any) { d["edges"].([]any)[0].(map[string]any)["state"] = "authenticated" }},
		{"execution argv", Invalid, func(d map[string]any) {
			d["items"].([]any)[0].(map[string]any)["executor"].(map[string]any)["argv"] = []any{"sh", "-c", "touch marker"}
		}},
		{"approval grant", Invalid, func(d map[string]any) { d["approval"] = true }},
		{"case alias", Invalid, func(d map[string]any) { d["items"].([]any)[0].(map[string]any)["id"] = "Example:block:intro" }},
		{"path traversal", Invalid, func(d map[string]any) { d["items"].([]any)[0].(map[string]any)["sourcePath"] = "../foreign" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]any
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			tc.mutate(d)
			b := wire(t, d)
			_, err := Decode(b)
			assertCode(t, err, tc.code)
			if err := schemaCheck(s, b); err == nil {
				t.Fatal("public schema accepted malformed wire")
			}
		})
	}
	for _, b := range [][]byte{append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"kind": "KnowledgeCatalog"`), []byte(`"kind":"KnowledgeCatalog","kind":"KnowledgeCatalog"`), 1), bytes.Repeat([]byte(" "), MaxBytes+1)} {
		_, err := Decode(b)
		assertCode(t, err, Invalid)
	}
}

func TestSemanticClosureAndPins(t *testing.T) {
	tests := []struct {
		name, code string
		mutate     func(*Catalog)
	}{
		{"duplicate namespaced identity", AmbiguousID, func(d *Catalog) { d.Items = append(d.Items, d.Items[0]) }},
		{"duplicate source alias", AmbiguousID, func(d *Catalog) { s := d.Sources[0]; s.ID = "example:source:other"; d.Sources = append(d.Sources, s) }},
		{"anchor drift", PinMismatch, func(d *Catalog) { d.Sources[0].Anchor.Commit = strings.Repeat("b", 40) }},
		{"algorithm drift", IncompletePin, func(d *Catalog) { d.Sources[0].Pin.CommitAlgorithm = "sha256" }},
		{"missing source closure", IncompletePin, func(d *Catalog) { d.Sources[0].Pin.Dependencies = []string{"missing"} }},
		{"source is actually item", Invalid, func(d *Catalog) { d.Items[1].SourceID = d.Items[0].ID }},
		{"missing workflow input", AmbiguousID, func(d *Catalog) { d.Items[1].Requires = []string{"example:block:missing"} }},
		{"missing static endpoint", Invalid, func(d *Catalog) { d.Edges[2].State = "static" }},
		{"duplicate relation", AmbiguousID, func(d *Catalog) { d.Edges = append(d.Edges, d.Edges[0]) }},
		{"unresolved quality is not a pass", Invalid, func(d *Catalog) { d.Items[0].Quality[0].State = "passed" }},
		{"implicit edge collision", AmbiguousID, func(d *Catalog) {
			d.Edges = append(d.Edges, Edge{From: d.Items[0].SourceID, To: d.Items[0].ID, Layer: "source", Relation: "anchors", State: "static"})
		}},
		{"projection bound", Invalid, func(d *Catalog) { d.Items[0].Requires = make([]string, 17) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { d, _ := fixture(t); tc.mutate(&d); assertCode(t, Validate(d), tc.code) })
	}
}

func TestGraphProjectionPreservesMetadataAndLayers(t *testing.T) {
	d, _ := fixture(t)
	g, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphdoc.Verify(g); err != nil {
		t.Fatal(err)
	}
	if g.Status != "partial" || len(g.Diagnostics) != 1 || g.Diagnostics[0].Code != Unresolved {
		t.Fatal("unresolved evidence lost")
	}
	layers := map[string]bool{}
	for _, e := range g.Edges {
		layers[e.Attributes["layer"]] = true
		if e.Provenance[0].Detected {
			t.Fatal("static declaration promoted to core detection")
		}
		if e.Attributes["evidenceState"] == "authenticated" {
			t.Fatal("invented trust")
		}
	}
	for _, layer := range []string{"source", "export", "semantic", "workflow", "package"} {
		if !layers[layer] {
			t.Fatalf("lost layer %s", layer)
		}
	}
	for _, it := range d.Items {
		found := false
		for _, n := range g.Nodes {
			if n.ID == it.ID {
				found = true
				var got Item
				if err := json.Unmarshal([]byte(n.Attributes["descriptor"]), &got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(wire(t, it), wire(t, got)) {
					t.Fatal("requires/produces/executor/quality/ownership/pins lost")
				}
				if n.Attributes["sourceEvidenceState"] != "" {
					t.Fatal("plain projection claimed authenticated")
				}
			}
		}
		if !found {
			t.Fatal("lost item")
		}
	}
	page, err := graphview.Render(g, graphview.Options{})
	if err != nil || !bytes.Contains(page, []byte(`example:skill:review`)) {
		t.Fatalf("existing graph consumer: %v", err)
	}
	raw, err := graphdoc.JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graphdoc.Decode(raw); err != nil {
		t.Fatal(err)
	}
	d.Items[0], d.Items[2] = d.Items[2], d.Items[0]
	d.Edges[0], d.Edges[2] = d.Edges[2], d.Edges[0]
	reordered, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	if reordered.Digest != g.Digest {
		t.Fatal("projection depends on input enumeration order")
	}
}

func TestExistingExportAndBlockContractsIntegration(t *testing.T) {
	d, _ := fixture(t)
	d.Items[0].Inputs = d.Items[1].Inputs
	d.Items[0].Inputs.ContextFloor = []string{d.Items[2].ID}
	sg, err := deps.BuildSourceGraph([]deps.PinnedSource{d.Sources[0].Pin})
	if err != nil {
		t.Fatal(err)
	}
	c := exports.Catalog{APIVersion: exports.CatalogAPIVersion, Provider: d.Sources[0].Pin.ProviderID, Source: sg.Nodes[0].Key, ContractDigest: d.Sources[0].Pin.ContractDigest, Exports: []exports.ExportEntry{*d.Items[0].Export}}
	exportRaw := wire(t, c)
	g, err := ProjectExportCatalog(d, d.Sources[0].ID, exportRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphdoc.Verify(g); err != nil {
		t.Fatal(err)
	}
	c.Exports[0].ToolDigest = "sha256:" + strings.Repeat("2", 64)
	_, err = ProjectExportCatalog(d, d.Sources[0].ID, wire(t, c))
	assertCode(t, err, SourceMismatch)
	c.Exports[0] = *d.Items[0].Export
	c.Source = "sha256:" + strings.Repeat("2", 64)
	_, err = ProjectExportCatalog(d, d.Sources[0].ID, wire(t, c))
	assertCode(t, err, SourceMismatch)
	blockRaw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "knowledge", "block-export.json"))
	if err != nil {
		t.Fatal(err)
	}
	g, err = ProjectBlockExport(d, d.Sources[0].ID, blockRaw)
	if err != nil {
		t.Fatal(err)
	}
	preserved := false
	for _, n := range g.Nodes {
		if n.ID == d.Items[0].ID {
			preserved = strings.Contains(n.Attributes["blockExport"], `"body":"blocks/intro.md"`) && strings.Contains(n.Attributes["blockExport"], `"formatter"`) && strings.Contains(n.Attributes["blockExport"], `"order":1`)
		}
	}
	if !preserved {
		t.Fatal("block provider/body/target/formatter metadata lost")
	}
	for _, n := range g.Nodes {
		if n.ID == d.Items[0].ID {
			var got Item
			if err := json.Unmarshal([]byte(n.Attributes["descriptor"]), &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire(t, got.Inputs), wire(t, d.Items[0].Inputs)) {
				t.Fatal("block adapter lost actual input definitions")
			}
		}
	}
	bad := bytes.ReplaceAll(blockRaw, []byte(`"provider": "synthetic"`), []byte(`"provider": "foreign"`))
	_, err = ProjectBlockExport(d, d.Sources[0].ID, bad)
	assertCode(t, err, SourceMismatch)
}

func TestSourceEdgesAndStableVersionedIdentity(t *testing.T) {
	d, _ := fixture(t)
	base := d.Sources[0]
	base.ID = "example:source:base"
	base.Pin.Alias = "base"
	base.Pin.Origin = "https://base.example.test/templates.git"
	base.Anchor.Origin = base.Pin.Origin
	d.Sources[0].Pin.Dependencies = []string{"base"}
	d.Sources = append(d.Sources, base)
	sg, err := deps.BuildSourceGraph([]deps.PinnedSource{d.Sources[0].Pin, base.Pin})
	if err != nil {
		t.Fatal(err)
	}
	old, err := graphview.FromContracts(sg, nil, nil)
	if err != nil || len(old.Edges) != 1 {
		t.Fatalf("existing source/export projection: %v", err)
	}
	g, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.From == base.ID && e.To == d.Sources[0].ID && e.Kind == "source:depends-on" {
			found = true
		}
	}
	if !found {
		t.Fatal("dependency direction or layer lost")
	}
	if err := schemaCheck(schema(t), wire(t, d)); err != nil {
		t.Fatal(err)
	}
	d.Version = "2.0.0"
	d.Items[0].Version = "2.0.0"
	d.Items[0].Export.Version = "2.0.0"
	next, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	if next.Digest == g.Digest || len(next.Nodes) != len(g.Nodes) {
		t.Fatal("version drift not represented")
	}
	for i := range next.Nodes {
		if next.Nodes[i].ID != g.Nodes[i].ID {
			t.Fatal("identity changed with version")
		}
	}
}
