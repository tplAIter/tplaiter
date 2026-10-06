package exports

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCompileAuthoredModifierPlanCarriesAllOperations(t *testing.T) {
	a := authoredFixture()
	ops := []string{"add", "replace", "remove", "keep", "compose", "retire", "replace-definition", "replace-active-association", "string-slots"}
	a.Rules = nil
	for i, operation := range ops {
		row := AuthoredOperation{ID: "rule-" + operation, Op: operation, Before: []string{}, After: []string{}, Source: "root", Kind: "file", Original: json.RawMessage(`{"Entry":{"path":"files/index.html","kind":"file","mode":"100644"},"Target":"index.html"}`)}
		if operation == "replace" {
			row.Export = "root.package.replaced"
		}
		if operation == "add" {
			row.Kind = ""
			row.Original = json.RawMessage(`null`)
			row.Export = "root.package.added"
		}
		before, after := true, true
		if operation == "add" {
			before = false
		}
		if operation == "remove" {
			after = false
		}
		key := "k" + string(rune('a'+i))
		expected := "old"
		beforeValue := "old"
		afterValue := "new"
		if !before {
			expected = ""
			beforeValue = ""
		}
		if !after {
			afterValue = ""
		}
		parentOriginal := `{"` + key + `":"old"}`
		parentAfter := `{"` + key + `":"new"}`
		if operation == "add" {
			parentOriginal = `{}`
		}
		if operation == "remove" {
			parentAfter = `{}`
		}
		row.Plan = &ModifierPlanRecord{ID: row.ID, Source: "root", ParentOriginal: json.RawMessage(parentOriginal), ParentAfter: json.RawMessage(parentAfter), Target: "package.json", Pointer: "/scripts/" + key, Op: operation, ExpectedPresence: before, ExpectedValue: expected, Before: ModifierPlanValue{Present: before, Value: beforeValue}, After: ModifierPlanValue{Present: after, Value: afterValue}}
		a.Rules = append(a.Rules, row)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompileAuthoredModifierPlan(raw); err != nil {
		t.Fatal(err)
	}
}

func authoredPlanFixture() AuthoredModifier {
	a := authoredFixture()
	a.Rules[0].ID = "keep.rule"
	a.Rules[0].Op = "keep"
	a.Rules[0].Plan = &ModifierPlanRecord{ID: "keep.rule", Source: "root", ParentOriginal: json.RawMessage(`{"lint":"old"}`), ParentAfter: json.RawMessage(`{"lint":"new"}`), Target: "package.json", Pointer: "/scripts/lint", Op: "keep", ExpectedPresence: true, ExpectedValue: "old", Before: ModifierPlanValue{Present: true, Value: "old"}, After: ModifierPlanValue{Present: true, Value: "new"}}
	return a
}

func TestAuthoredPlanStrictNegativeParity(t *testing.T) {
	valid := mustJSON(authoredPlanFixture())
	if _, err := ParseAuthoredModifier(valid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"duplicate nested key":     strings.Replace(string(valid), `"plan":{"id":"keep.rule","source"`, `"plan":{"id":"keep.rule","id":"duplicate","source"`, 1),
		"unknown nested field":     strings.Replace(string(valid), `"plan":{"id"`, `"plan":{"unknown":true,"id"`, 1),
		"nonnull parent primitive": strings.Replace(string(valid), `"parentOriginal":{"lint":"old"}`, `"parentOriginal":"bad"`, 1),
		"detached plan":            strings.Replace(string(valid), `"plan":{"id":"keep.rule"`, `"plan":{"id":"other.rule"`, 1),
		"parent before mismatch":   strings.Replace(string(valid), `"lint":"old"},"parentAfter"`, `"lint":"wrong"},"parentAfter"`, 1),
		"parent after mismatch":    strings.Replace(string(valid), `"lint":"new"},"target"`, `"lint":"wrong"},"target"`, 1),
		"missing nested field":     strings.Replace(string(valid), `,"successorSelector":""`, "", 1),
		"folded nested field":      strings.Replace(string(valid), `"plan":{"id":"keep.rule"`, `"plan":{"ID":"keep.rule"`, 1),
		"null nested boolean":      strings.Replace(string(valid), `"expectedPresence":true`, `"expectedPresence":null`, 1),
		"null nested plan":         strings.Replace(string(valid), `"plan":{"id":"keep.rule","source":"root","parentOriginal":{"lint":"old"},"parentAfter":{"lint":"new"},"target":"package.json","pointer":"/scripts/lint","op":"keep","expectedPresence":true,"expectedValue":"old","successorSelector":"","before":{"present":true,"value":"old"},"after":{"present":true,"value":"new"}}`, `"plan":null`, 1),
		"new op bad kind":          strings.Replace(string(valid), `"kind":"file"`, `"kind":"bogus"`, 1),
		"new op bad original":      invalidOriginal(valid),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAuthoredModifier([]byte(wire)); err == nil {
				t.Fatal("invalid authored plan accepted")
			}
		})
	}
}

func invalidOriginal(valid []byte) string {
	var wire map[string]any
	if err := json.Unmarshal(valid, &wire); err != nil {
		panic(err)
	}
	rules := wire["ruleConstraints"].([]any)
	rules[0].(map[string]any)["original"] = true
	result, err := json.Marshal(wire)
	if err != nil {
		panic(err)
	}
	return string(result)
}

func TestAuthoredPlanAllowsWholeFilePointer(t *testing.T) {
	a := authoredPlanFixture()
	a.Rules[0].Plan.Pointer = ""
	a.Rules[0].Plan.ParentOriginal = json.RawMessage(`null`)
	a.Rules[0].Plan.ParentAfter = json.RawMessage(`null`)
	if _, err := ParseAuthoredModifier(mustJSON(a)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthoredPlanSchemaRequiresTypedPlan(t *testing.T) {
	raw, err := os.ReadFile("../../schema/modifier-authored.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	const uri = "https://tplaiter.dev/schema/modifier-authored.v2.schema.json"
	if err = c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	valid := mustJSON(authoredPlanFixture())
	value, err := js.UnmarshalJSON(strings.NewReader(string(valid)))
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(value); err != nil {
		t.Fatal(err)
	}
	var missing map[string]any
	if err = json.Unmarshal(valid, &missing); err != nil {
		t.Fatal(err)
	}
	rules := missing["ruleConstraints"].([]any)
	delete(rules[0].(map[string]any), "plan")
	withoutPlan, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	value, err = js.UnmarshalJSON(strings.NewReader(string(withoutPlan)))
	if err != nil {
		t.Fatal(err)
	}
	if schema.Validate(value) == nil {
		t.Fatal("schema accepted six-op row without plan")
	}
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
