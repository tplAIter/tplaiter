package exports

import (
	"encoding/json"
	js "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func authoredFixture() AuthoredModifier {
	h := "sha256:" + strings.Repeat("0", 64)
	return AuthoredModifier{APIVersion: AuthoredModifierAPIVersion, Kind: "Modifier", Metadata: Metadata{ID: "test.modifier", Version: "1.0.0"}, Compatibility: Compatibility{MinimumCLI: "0.1.0", PortableAPI: "tplaiter.dev/portable/v1", Runtimes: []string{"bun"}, Layouts: []string{"react"}}, Sources: []AuthoredSourceConstraint{{Alias: "root", Origin: "https://github.com/example/public", TemplatePath: ".", CommitAlgorithm: "sha1", Commit: strings.Repeat("0", 40), TreeDigest: h, ContentDigest: h, ContractDigest: h, Parameters: []deps.Parameter{}, Dependencies: []string{}}}, SelfSource: "root", Requires: Requires{Exports: []ExportRequirement{}, Capabilities: []Capability{}}, Provides: []ProvidedCapability{}, Conflicts: []Capability{}, Replaces: []Replacement{}, Bindings: []Binding{}, ToolConstraints: []ToolConstraint{}, Renames: []Rename{}, Rules: []AuthoredOperation{{ID: "remove.file", Op: "remove", Before: []string{}, After: []string{}, Source: "root", Kind: "file", Original: json.RawMessage(`{"Entry":{"path":"files/index.html","kind":"file","mode":"100644","contentSHA256":"` + h + `"},"Target":"index.html"}`), Export: ""}}}
}
func TestAuthoredModifierClosedRecords(t *testing.T) {
	fixture := authoredFixture()
	raw, e := json.Marshal(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseAuthoredModifier(raw); e != nil {
		t.Fatal(e)
	}
	tests := map[string]string{
		"duplicate":                strings.Replace(string(raw), `"kind":"Modifier"`, `"kind":"Modifier","kind":"Modifier"`, 1),
		"authority":                strings.Replace(string(raw), `"sourceConstraints":[{`, `"sourceConstraints":[{"providerId":"caller",`, 1),
		"nested":                   strings.Replace(string(raw), `"Target":"index.html"`, `"Target":"index.html","permit":true`, 1),
		"missing-operation-export": strings.Replace(string(raw), `,"export":""`, "", 1),
		"null-parameters":          strings.Replace(string(raw), `"parameters":[]`, `"parameters":null`, 1),
		"version":                  strings.Replace(string(raw), `"version":"1.0.0"`, `"version":"01.0.0"`, 1),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseAuthoredModifier([]byte(b)); e == nil {
				t.Fatal("invalid authored record accepted")
			}
		})
	}
	if _, e = ParseAuthoredModifier([]byte(strings.Repeat(" ", 1<<20+1))); e == nil {
		t.Fatal("oversize accepted")
	}
}

func TestAuthoredSchemaClosedParity(t *testing.T) {
	raw, e := os.ReadFile("../../schema/modifier-authored.v2.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	doc, e := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if e != nil {
		t.Fatal(e)
	}
	c := js.NewCompiler()
	uri := "https://tplaiter.dev/schema/modifier-authored.v2.schema.json"
	if e = c.AddResource(uri, doc); e != nil {
		t.Fatal(e)
	}
	schema, e := c.Compile(uri)
	if e != nil {
		t.Fatal(e)
	}
	valid, _ := json.Marshal(authoredFixture())
	generator := authoredFixture()
	generator.Rules[0].Kind = "generator"
	generator.Rules[0].Original, e = json.Marshal(struct {
		Generator manifest.Generator
		Resources []trustverify.SourceEntry
	}{Generator: manifest.Generator{Params: []manifest.Param{{Name: "name", Default: "Widget"}}}})
	if e != nil {
		t.Fatal(e)
	}
	generatorWire, e := json.Marshal(generator)
	if e != nil {
		t.Fatal(e)
	}
	wires := []string{string(generatorWire), strings.Replace(string(generatorWire), `"Generator":`, `"generator":`, 1), string(valid), strings.Replace(string(valid), `"sourceConstraints":[{`, `"sourceConstraints":[{"evidenceDigest":"caller",`, 1), strings.Replace(string(valid), `"Target":"index.html"`, `"Target":"index.html","permit":true`, 1)}
	for _, wire := range wires {
		v, e := js.UnmarshalJSON(strings.NewReader(wire))
		if e != nil {
			t.Fatal(e)
		}
		schemaErr := schema.Validate(v)
		_, parseErr := ParseAuthoredModifier([]byte(wire))
		if (schemaErr == nil) != (parseErr == nil) {
			t.Fatalf("schema/parser parity: %v/%v", schemaErr, parseErr)
		}
	}
}
