package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const schemaPath = "../../schema/template.manifest.schema.json"

// TestSchema_ValidJSON: the schema is syntactically valid JSON with the
// expected structure.
//
// Validation approach: do not add an external JSON Schema validator
// (santhosh-tekuri/jsonschema) for one test, which would add transitive
// dependencies to go.mod. Instead, validate the schema as JSON and perform a
// smoke check: every top-level field from the full example (full.yaml) appears
// in the schema's properties. Full JSON Schema validation for IDE use is left
// to the editor via $schema/$id.
func TestSchema_ValidJSON(t *testing.T) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	for _, key := range []string{"$schema", "$id", "type", "properties", "required", "$defs"} {
		if _, ok := schema[key]; !ok {
			t.Errorf("schema is missing key %q", key)
		}
	}
}

func TestSchema_CoversFullExample(t *testing.T) {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatalf("parsing schema: %v", err)
	}

	fullData, err := os.ReadFile(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("reading full.yaml: %v", err)
	}
	var full map[string]any
	if err := yaml.Unmarshal(fullData, &full); err != nil {
		t.Fatalf("parsing full.yaml: %v", err)
	}

	for key := range full {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("top-level field %q from full.yaml is not covered by the schema", key)
		}
	}
}

func TestSchemaClosedMigrationContract(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	if props["migrations"].(map[string]any)["items"].(map[string]any)["$ref"] != "#/$defs/migration" {
		t.Fatal("missing migration property")
	}
	migration := schema["$defs"].(map[string]any)["migration"].(map[string]any)
	if migration["additionalProperties"] != false {
		t.Fatal("open migration schema")
	}
	step := migration["properties"].(map[string]any)["steps"].(map[string]any)["items"].(map[string]any)
	if step["additionalProperties"] != false || len(step["oneOf"].([]any)) != 2 {
		t.Fatal("open executable schema")
	}
}

func TestDeprecatedSchemaClosedBoolean(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"settingGroup", "option"} {
		d := s["$defs"].(map[string]any)[key].(map[string]any)
		if d["additionalProperties"] != false {
			t.Fatal("schema opened")
		}
		prop := d["properties"].(map[string]any)["deprecated"].(map[string]any)
		if prop["type"] != "boolean" || prop["default"] != false {
			t.Fatal(prop)
		}
	}
}

func TestSchemaGeneratorParameterPatternRuntimeParity(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("bad schema JSON")
	}
	fragment := document["$defs"].(map[string]any)["param"]
	encoded, _ := json.Marshal(fragment)
	parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("parameter.schema.json", parsed); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("parameter.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                string
		parameter           map[string]any
		schemaOK, runtimeOK bool
	}{
		{"string SQL identifier", map[string]any{"name": "table", "type": "string", "required": true, "pattern": "^[a-z_][a-z0-9_]*$"}, true, true},
		{"int pattern", map[string]any{"name": "port", "type": "int", "pattern": "^[1-9][0-9]*$"}, true, true},
		{"bool pattern absent", map[string]any{"name": "enabled", "type": "bool"}, true, true},
		{"bool empty pattern ignored", map[string]any{"name": "enabled", "type": "bool", "pattern": ""}, true, true},
		{"fields empty pattern ignored", map[string]any{"name": "fields", "type": "fields", "pattern": ""}, true, true},
		{"bool nonempty pattern refused", map[string]any{"name": "enabled", "type": "bool", "pattern": "true"}, false, false},
		{"fields nonempty pattern refused", map[string]any{"name": "fields", "type": "fields", "pattern": ".+"}, false, false},
		{"pattern collection wrongkind refused", map[string]any{"name": "table", "type": "string", "pattern": []string{"a"}}, false, false},
		// The existing YAML decoder coerces numeric scalars into Go string fields.
		// The JSON schema stays typed; this patch does not change that codec.
		{"numeric YAML scalar existing coercion", map[string]any{"name": "table", "type": "string", "pattern": 12}, false, true},
		{"unknown field refused", map[string]any{"name": "table", "type": "string", "unknownConstraint": true}, false, false},
		// JSONSchema declares value shape. RE2 compilation remains the actual
		// normal runtime check before any generator rendering, not a schema grant.
		{"malformed RE2 runtime refusal", map[string]any{"name": "table", "type": "string", "pattern": "["}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := json.Marshal(tc.parameter)
			value, e := jsonschema.UnmarshalJSON(bytes.NewReader(input))
			if e != nil {
				t.Fatal(e)
			}
			if accepted := compiled.Validate(value) == nil; accepted != tc.schemaOK {
				t.Fatalf("compiled schema accepted=%v want%v", accepted, tc.schemaOK)
			}
			yamlInput, e := yaml.Marshal(map[string]any{"apiVersion": APIVersion, "kind": "Template", "metadata": map[string]any{"name": "neutral", "version": "1.0.0"}, "engine": map[string]any{"type": "gotemplate", "root": "files"}, "generators": []any{map[string]any{"kind": "migration", "snippet": "migration.sql.tmpl", "target": "migrations/output.sql", "params": []any{tc.parameter}}}})
			if e != nil {
				t.Fatal(e)
			}
			template, e := ParseTemplate(yamlInput)
			if e == nil {
				e = template.Validate()
			}
			if accepted := e == nil; accepted != tc.runtimeOK {
				t.Fatalf("normal manifest accepted=%v want%v: %v", accepted, tc.runtimeOK, e)
			}
		})
	}
}
