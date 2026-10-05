package manifest

import (
	"encoding/json"
	"os"
	"testing"

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
