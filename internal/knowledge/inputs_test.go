package knowledge

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

func TestInputDefinitionsRoundTripAndContextFloor(t *testing.T) {
	d, raw := fixture(t)
	in := d.Items[1].Inputs
	if !in.Definitions[0].Required || in.Definitions[0].Default != nil || in.Definitions[1].Required || string(in.Definitions[1].Default) != "false" || string(in.Definitions[2].Default) != "null" {
		t.Fatal("required/optional or absent/false/null collapsed")
	}
	if err := schemaCheck(schema(t), raw); err != nil {
		t.Fatal(err)
	}
	zero := 0
	d.Items[1].Inputs.Definitions[0].Constraints.MinLength = &zero
	d.Items[1].Inputs.Definitions[0].Constraints.MaxLength = &zero
	emptyPattern := ""
	d.Items[1].Inputs.Definitions[0].Constraints.Pattern = &emptyPattern
	encodedZero := wire(t, d)
	if !bytes.Contains(encodedZero, []byte(`"minLength":0`)) || !bytes.Contains(encodedZero, []byte(`"maxLength":0`)) {
		t.Fatal("zero bounds collapsed to absence")
	}
	d, err := Decode(encodedZero)
	if err != nil {
		t.Fatal(err)
	}
	in = d.Items[1].Inputs
	g, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, edge := range g.Edges {
		if edge.Kind == "workflow:context-floor" && edge.From == in.ContextFloor[0] && edge.To == d.Items[1].ID {
			found = true
		}
	}
	if !found {
		t.Fatal("context floor lost")
	}
	for _, n := range g.Nodes {
		if n.ID == d.Items[1].ID {
			var got Item
			if err := json.Unmarshal([]byte(n.Attributes["descriptor"]), &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire(t, in), wire(t, got.Inputs)) {
				t.Fatal("input semantics lost")
			}
		}
	}
	encoded := wire(t, d)
	again, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire(t, in), wire(t, again.Items[1].Inputs)) {
		t.Fatal("wire roundtrip lost inputs")
	}
}

func TestInputInvalidSemanticsAndClosedSchema(t *testing.T) {
	cases := []struct {
		name, code   string
		mutate       func(map[string]any)
		schemaReject bool
	}{
		{"missing required status", Invalid, func(d map[string]any) { delete(d, "required") }, true},
		{"required null", Invalid, func(d map[string]any) { d["required"] = nil }, true},
		{"nonnullable default null", Invalid, func(d map[string]any) { d["default"] = nil }, true},
		{"wrong default type", Invalid, func(d map[string]any) { d["default"] = false }, true},
		{"default below length floor", Invalid, func(d map[string]any) { d["default"] = "" }, false},
		{"default violates pattern", Invalid, func(d map[string]any) { d["default"] = "UPPER" }, false},
		{"inverted lengths", Invalid, func(d map[string]any) { d["constraints"].(map[string]any)["maxLength"] = 0 }, false},
		{"invalid pattern", Invalid, func(d map[string]any) { d["constraints"].(map[string]any)["pattern"] = "[" }, false},
		{"exec constraint", Invalid, func(d map[string]any) { d["constraints"].(map[string]any)["command"] = "sh" }, true},
		{"caller authority", Invalid, func(d map[string]any) { d["approved"] = true }, true},
	}
	s := schema(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, raw := fixture(t)
			var d map[string]any
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			definition := d["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["definitions"].([]any)[0].(map[string]any)
			tc.mutate(definition)
			b := wire(t, d)
			_, err := Decode(b)
			assertCode(t, err, tc.code)
			if tc.schemaReject && schemaCheck(s, b) == nil {
				t.Fatal("schema accepted invalid input shape")
			}
		})
	}
	for _, tc := range []struct {
		name, code string
		mutate     func(*Catalog)
	}{
		{"unknown inputs major", UnsupportedVersion, func(d *Catalog) { d.Items[1].Inputs.APIVersion = "tplaiter.dev/knowledge-inputs/v2" }},
		{"duplicate input", Invalid, func(d *Catalog) {
			d.Items[1].Inputs.Definitions = append(d.Items[1].Inputs.Definitions, d.Items[1].Inputs.Definitions[0])
		}},
		{"missing context floor", AmbiguousID, func(d *Catalog) { d.Items[1].Inputs.ContextFloor = []string{"example:resource:missing"} }},
		{"integer minimum", Invalid, func(d *Catalog) { d.Items[1].Inputs.Definitions[2].Default = json.RawMessage(`-1`) }},
		{"integer enum", Invalid, func(d *Catalog) { d.Items[1].Inputs.Definitions[2].Default = json.RawMessage(`5`) }},
		{"unsafe integer", Invalid, func(d *Catalog) { d.Items[1].Inputs.Definitions[2].Default = json.RawMessage(`9007199254740992`) }},
		{"integer noncanonical lexeme", Invalid, func(d *Catalog) { d.Items[1].Inputs.Definitions[2].Default = json.RawMessage(`0.0`) }},
		{"boolean false preserved", Invalid, func(d *Catalog) { d.Items[1].Inputs.Definitions[1].Default = json.RawMessage(`0`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := fixture(t)
			tc.mutate(&d)
			_, err := Decode(wire(t, d))
			assertCode(t, err, tc.code)
		})
	}
}

func TestNullAllowanceConfinedAndScalarLexemesPreserved(t *testing.T) {
	d, _ := fixture(t)
	d.Sources[0].Pin.Parameters = []deps.Parameter{{Name: "count", Value: json.RawMessage(`1.0`)}}
	_, err := Decode(wire(t, d))
	assertCode(t, err, IncompletePin)
	_, raw := fixture(t)
	for _, mutation := range []func(map[string]any){
		func(d map[string]any) {
			d["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["contextFloor"] = nil
		},
		func(d map[string]any) {
			d["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["definitions"] = nil
		},
		func(d map[string]any) {
			d["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["definitions"].([]any)[0].(map[string]any)["constraints"] = nil
		},
	} {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mutation(m)
		_, err := Decode(wire(t, m))
		assertCode(t, err, Invalid)
	}
}

func TestIndependentEmptyPatternConcordance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		index int
	}{{"boolean", 1}, {"integer", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			_, raw := fixture(t)
			var d map[string]any
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			definition := d["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["definitions"].([]any)[tc.index].(map[string]any)
			definition["constraints"].(map[string]any)["pattern"] = ""
			b := wire(t, d)
			_, runtimeErr := Decode(b)
			schemaErr := schemaCheck(schema(t), b)
			t.Logf("runtimeAccepted=%v schemaAccepted=%v", runtimeErr == nil, schemaErr == nil)
			if runtimeErr == nil && schemaErr != nil {
				t.Fatal("runtime accepts explicitly forbidden string constraint on non-string input")
			}
		})
	}
}

func TestPatternPresenceSchemaRuntimeAndProjection(t *testing.T) {
	s := schema(t)
	for _, tc := range []struct {
		name  string
		index int
	}{{"string", 0}, {"boolean", 1}, {"integer", 2}} {
		for _, pattern := range []*string{nil, new(string), ptrPattern("^ok$")} {
			t.Run(tc.name+"/"+patternLabel(pattern), func(t *testing.T) {
				d, _ := fixture(t)
				d.Items[1].Inputs.Definitions[tc.index].Constraints.Pattern = pattern
				if tc.name == "string" {
					d.Items[1].Inputs.Definitions[tc.index].Default = json.RawMessage(`"ok"`)
				}
				accepted := tc.name == "string" || pattern == nil
				// A string default exercises both absent and explicitly empty pattern matching.
				raw := wire(t, d)
				decoded, decodeErr := Decode(raw)
				validateErr := Validate(d)
				schemaErr := schemaCheck(s, raw)
				if accepted {
					if decodeErr != nil || validateErr != nil || schemaErr != nil {
						t.Fatalf("valid pattern: decode=%v validate=%v schema=%v", decodeErr, validateErr, schemaErr)
					}
					got := decoded.Items[1].Inputs.Definitions[tc.index].Constraints.Pattern
					if (pattern == nil) != (got == nil) || (pattern != nil && *pattern != *got) {
						t.Fatal("pattern presence lost")
					}
					graph, err := Project(decoded)
					if err != nil {
						t.Fatal(err)
					}
					for _, node := range graph.Nodes {
						if node.ID == d.Items[1].ID {
							var item Item
							if err := json.Unmarshal([]byte(node.Attributes["descriptor"]), &item); err != nil {
								t.Fatal(err)
							}
							got := item.Inputs.Definitions[tc.index].Constraints.Pattern
							if (pattern == nil) != (got == nil) || (pattern != nil && *pattern != *got) {
								t.Fatal("graph lost explicit empty pattern")
							}
						}
					}
				} else {
					assertCode(t, decodeErr, Invalid)
					assertCode(t, validateErr, Invalid)
					if schemaErr == nil {
						t.Fatal("schema accepted forbidden pattern")
					}
				}
			})
		}
	}
	d, _ := fixture(t)
	var obj map[string]any
	if err := json.Unmarshal(wire(t, d), &obj); err != nil {
		t.Fatal(err)
	}
	constraints := obj["items"].([]any)[1].(map[string]any)["inputs"].(map[string]any)["definitions"].([]any)[0].(map[string]any)["constraints"].(map[string]any)
	constraints["pattern"] = nil
	raw := wire(t, obj)
	_, err := Decode(raw)
	assertCode(t, err, Invalid)
	if schemaCheck(s, raw) == nil {
		t.Fatal("null pattern admitted")
	}
}

func ptrPattern(s string) *string { return &s }
func patternLabel(s *string) string {
	if s == nil {
		return "absent"
	}
	if *s == "" {
		return "empty"
	}
	return "nonempty"
}
