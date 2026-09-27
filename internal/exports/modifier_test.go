package exports

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSyntheticModifierAndStrictFailures(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Metadata.ID != "next-app" || len(m.Rules) != 3 {
		t.Fatalf("unexpected model: %#v", m.Metadata)
	}
	if _, err := Parse(append([]byte("---\n"), b...)); err != nil {
		t.Fatalf("YAML one-document parse: %v", err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(b, []byte(`"kind": "Modifier"`), []byte(`"Kind": "Modifier"`), 1),
		append(append([]byte{}, b...), []byte("\n{}")...),
		bytes.Replace(b, []byte(`"commit": "0000000000000000000000000000000000000000"`), []byte(`"commit": "bad"`), 1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("accepted invalid modifier")
		}
	}
}

func TestParseStrictShapeParity(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Modifier)
	}{
		{"object binding", func(m *Modifier) { m.Bindings = []Binding{{Name: "x", Value: json.RawMessage(`{"x":true}`)}} }},
		{"selector", func(m *Modifier) { m.Rules[0].Export = "next.unknown.name.extra" }},
		{"origin", func(m *Modifier) { m.Sources[0].Origin = "not-a-url" }},
		{"semver", func(m *Modifier) { m.Metadata.Version = "1.2.3-01" }},
		{"tool digest", func(m *Modifier) {
			m.ToolConstraints = []ToolConstraint{{ID: "tool", CompatibleRange: "*", OptionsDigest: "bad"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(b)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&m)
			if err := Validate(m); err == nil {
				t.Fatal("accepted invalid direct model")
			}
			raw, _ := json.Marshal(m)
			if _, err := Parse(raw); err == nil {
				t.Fatal("accepted invalid document")
			}
		})
	}
}

func TestResolveDeterministicAndReplacementPreconditions(t *testing.T) {
	base := RuleSet{Rules: []Rule{{ID: "react.router", Digest: "sha256:" + zeros, Provider: "react", Capabilities: []Capability{{Name: "runtime", Value: "react-spa"}, {Name: "router", Value: "react-router"}}}, {ID: "react.build", Digest: "sha256:" + zeros, Provider: "react"}}, Required: []Capability{{Name: "runtime", Value: "next-app"}, {Name: "router", Value: "next-app-router"}}, Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros, Version: "0.0.0"}}}
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ResolveModifiers(base, []Modifier{m})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tombstones) == 0 || len(c.Rules) == 0 {
		t.Fatalf("incomplete composition: %#v", c)
	}
	for _, r := range c.Rules {
		if r.ID == "next.router" && r.Digest == m.Rules[0].ExpectedDigest {
			t.Fatal("replacement output reused its old expected digest")
		}
	}
	m.Rules[0].ExpectedDigest = "sha256:" + strings.Repeat("1", 64)
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil {
		t.Fatal("accepted stale precondition")
	}
}

// TestModifierSchemaFacetMatrix keeps normal boundary coverage in the product
// suite. Parse owns raw property-presence checks; Validate owns typed values.
func TestModifierSchemaFacetMatrix(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	reject := map[string][]byte{
		"requested-ref-1025":         bytes.Replace(base, []byte(`"synthetic-v0.0.0"`), []byte(`"`+strings.Repeat("x", 1025)+`"`), 1),
		"export-range-1025":          bytes.Replace(base, []byte(`">=0.0.0-0 <1.0.0"`), []byte(`"`+strings.Repeat("x", 1025)+`"`), 1),
		"add-forbidden-empty-target": bytes.Replace(base, []byte(`"op": "add",`), []byte(`"op": "add", "target": "",`), 1),
		"control-path":               bytes.Replace(base, []byte(`"templatePath": "."`), []byte(`"templatePath": "line\nbreak"`), 1),
	}
	for name, raw := range reject {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("accepted invalid wire facet")
			}
		})
	}
	for _, count := range []int{32768, 20000} {
		t.Run("binding-codepoints", func(t *testing.T) {
			value := strings.Repeat("x", count)
			if count == 20000 {
				value = strings.Repeat("é", count)
			}
			raw, _ := json.Marshal(value)
			candidate := bytes.Replace(base, []byte(`"bindings": []`), append([]byte(`"bindings": [{"name":"x","value":`), append(raw, []byte(`}]`)...)...), 1)
			if _, err := Parse(candidate); err != nil {
				t.Fatalf("schema-valid code-point boundary rejected: %v", err)
			}
		})
	}
	for _, yamlDoc := range []string{
		"metadata: &bad {}\n",
		"!custom {}\n",
	} {
		t.Run("yaml-policy", func(t *testing.T) {
			if _, err := Parse([]byte(yamlDoc)); err == nil {
				t.Fatal("invalid YAML syntax policy accepted")
			}
		})
	}
}

func TestValidateTypedFacetBoundaries(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Compatibility.Runtimes = []string{"react.spa"}
	if err := Validate(m); err != nil {
		t.Fatalf("dotted runtime rejected: %v", err)
	}
	m.Requires.Exports[0].CompatibleRange = strings.Repeat("x", 1025)
	if err := Validate(m); err == nil {
		t.Fatal("overlong typed range accepted")
	}
}

func TestGraphConstraintBoundaries(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	base := RuleSet{Rules: []Rule{{ID: "old", Digest: "sha256:" + zeros, Version: "1.0.0", Provider: "react", Capabilities: []Capability{{Name: "runtime", Value: "old"}}}}, Required: []Capability{{Name: "runtime", Value: "next-app"}}, Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros, Version: "0.0.0"}}}
	m.Rules = []Operation{{ID: "new", Op: "replace", Target: "old", ExpectedDigest: "sha256:" + zeros, ExpectedVersion: "2.0.0", Export: "next.block.new", Before: []string{}, After: []string{}}}
	m.Provides = []ProvidedCapability{{Name: "runtime", Value: "next-app", RuleID: "new"}}
	m.Conflicts = []Capability{}
	m.Replaces = []Replacement{}
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil {
		t.Fatal("wrong expected version accepted")
	}
	m.Rules[0].ExpectedVersion = "1.0.0"
	base.Rules = append(base.Rules, Rule{ID: "other", Digest: "sha256:" + zeros, Capabilities: []Capability{{Name: "router", Value: "one"}}}, Rule{ID: "other2", Digest: "sha256:" + zeros, Capabilities: []Capability{{Name: "router", Value: "two"}}})
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil {
		t.Fatal("unconditional duplicate router accepted")
	}
}

func TestGraphTargetProducerAndTombstone(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Requires = Requires{Exports: []ExportRequirement{}, Capabilities: []Capability{}}
	m.Provides = []ProvidedCapability{}
	m.Conflicts = []Capability{}
	m.Replaces = []Replacement{}
	m.Rules = []Operation{{ID: "z.first", Op: "add", Export: "next.block.z", Before: []string{}, After: []string{}}, {ID: "a.second", Op: "replace", Target: "z.first", Export: "next.block.a", Before: []string{}, After: []string{}}}
	first, err := ruleFor(operationRef{m: m, op: m.Rules[0]}, RuleSet{})
	if err != nil {
		t.Fatal(err)
	}
	m.Rules[1].ExpectedDigest = first.Digest
	if _, err := ResolveModifiers(RuleSet{}, []Modifier{m}); err != nil {
		t.Fatalf("producer chain rejected: %v", err)
	}
	m.Rules = []Operation{{ID: "remove", Op: "remove", Target: "old", ExpectedDigest: "sha256:" + zeros, Before: []string{}, After: []string{}}, {ID: "old", Op: "add", Export: "next.block.old", Before: []string{}, After: []string{"remove"}}}
	if _, err := ResolveModifiers(RuleSet{Rules: []Rule{{ID: "old", Digest: "sha256:" + zeros}}}, []Modifier{m}); err == nil {
		t.Fatal("tombstone resurrection accepted")
	}
}

func TestGraphFactAndCycleBoundaries(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	base := RuleSet{Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros}}}
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil {
		t.Fatal("missing export version accepted")
	}
	m.Requires.Exports = []ExportRequirement{}
	m.Requires.Capabilities = []Capability{}
	m.Provides = []ProvidedCapability{}
	m.Conflicts = []Capability{}
	m.Replaces = []Replacement{}
	m.Rules = []Operation{{ID: "a", Op: "add", Export: "next.block.a", Before: []string{"b"}, After: []string{}}, {ID: "b", Op: "add", Export: "next.block.b", Before: []string{"a"}, After: []string{}}, {ID: "downstream", Op: "add", Export: "next.block.d", Before: []string{}, After: []string{"a"}}}
	if _, err := ResolveModifiers(RuleSet{}, []Modifier{m}); err == nil || !strings.Contains(err.Error(), "a -> b -> a") {
		t.Fatalf("closed cycle path missing: %v", err)
	}
	if _, err := ResolveModifiers(RuleSet{Rules: []Rule{{ID: "retired"}}, Tombstones: []Tombstone{{ID: "retired"}}}, []Modifier{m}); err == nil {
		t.Fatal("active prior tombstone coexistence accepted")
	}
}

func TestGraphFinalConstraintsCheckEveryModifier(t *testing.T) {

	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	first, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	base := RuleSet{
		Rules: []Rule{
			{ID: "react.router", Digest: "sha256:" + zeros, Provider: "react", Capabilities: []Capability{{Name: "runtime", Value: "react-spa"}, {Name: "router", Value: "react-router"}}},
			{ID: "react.build", Digest: "sha256:" + zeros, Provider: "react"},
		},
		Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros, Version: "0.0.0"}},
	}
	newLater := func() Modifier {
		later := first
		later.Metadata.ID = "later"
		later.Requires = Requires{Exports: []ExportRequirement{}, Capabilities: []Capability{}}
		later.Provides = []ProvidedCapability{}
		later.Conflicts = []Capability{}
		later.Replaces = []Replacement{}
		later.Rules = []Operation{{ID: "later.rule", Op: "add", Export: "next.block.later", Before: []string{}, After: []string{}}}
		return later
	}

	later := newLater()
	later.Conflicts = []Capability{{Name: "runtime", Value: "next-app"}}
	if _, err := ResolveModifiers(base, []Modifier{first, later}); err == nil || !strings.Contains(err.Error(), "CAPABILITY_CONFLICT") {
		t.Fatalf("later modifier conflict was skipped: %v", err)
	}

	later = newLater()
	// Both rule IDs exist in the final candidate, but this declared retired
	// capability value does not belong to react.router.
	later.Replaces = []Replacement{{Name: "runtime", Value: "unrelated", ProviderRule: "react.router", WithRule: "next.router"}}
	if _, err := ResolveModifiers(base, []Modifier{first, later}); err == nil || !strings.Contains(err.Error(), "REPLACEMENT_INVALID") {
		t.Fatalf("later modifier replacement was skipped: %v", err)
	}
}

func TestGraphFactRangeAndToolBoundaries(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Rules = []Operation{{ID: "single", Op: "add", Export: "next.block.single", Before: []string{}, After: []string{}}}
	m.Provides = []ProvidedCapability{}
	m.Requires.Capabilities = []Capability{}
	m.Conflicts = []Capability{}
	m.Replaces = []Replacement{}
	base := RuleSet{Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros, Version: "1.0.0"}}}
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil || !strings.Contains(err.Error(), "EXPORT_FACT_MISMATCH") {
		t.Fatalf("incompatible export version accepted: %v", err)
	}

	m.Requires.Exports = []ExportRequirement{}
	m.ToolConstraints = []ToolConstraint{{ID: "formatter", CompatibleRange: ">=1.0.0 <2.0.0", OptionsDigest: "sha256:" + zeros}}
	if _, err := ResolveModifiers(RuleSet{}, []Modifier{m}); err == nil || !strings.Contains(err.Error(), "TOOL_CONSTRAINT_UNSUPPORTED") {
		t.Fatalf("missing tool fact accepted: %v", err)
	}
	base.Tools = map[string]ToolFact{"formatter": {Version: "2.0.0", OptionsDigest: "sha256:" + zeros}}
	if _, err := ResolveModifiers(base, []Modifier{m}); err == nil || !strings.Contains(err.Error(), "TOOL_CONSTRAINT_MISMATCH") {
		t.Fatalf("incompatible tool fact accepted: %v", err)
	}
	m.ToolConstraints[0].CompatibleRange = "<1.0.0-10"
	base.Tools["formatter"] = ToolFact{Version: "1.0.0-2", OptionsDigest: "sha256:" + zeros}
	if _, err := ResolveModifiers(base, []Modifier{m}); err != nil {
		t.Fatalf("numeric prerelease fact rejected: %v", err)
	}
}

func TestSemVerPrecedence(t *testing.T) {
	// SemVer 2.0.0's published precedence sequence. Build metadata is ignored.
	ordered := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	}
	for i := 0; i+1 < len(ordered); i++ {
		if got := compareSemver(ordered[i], ordered[i+1]); got >= 0 {
			t.Fatalf("precedence %q < %q: got %d", ordered[i], ordered[i+1], got)
		}
	}
	for _, tc := range []struct {
		version, constraint string
		want                bool
	}{
		{"1.0.0-2", "<1.0.0-10", true},
		{"1.0.0-10", "<1.0.0-2", false},
		{"1.0.0-1", "<1.0.0-alpha", true},
		{"1.0.0-alpha", "<1.0.0-1", false},
		{"1.0.0+build.1", "=1.0.0+build.2", true},
		{"1.0.0-999999999999999999999999999999", ">1.0.0-2", true},
	} {
		if got := versionMatches(tc.version, tc.constraint); got != tc.want {
			t.Fatalf("versionMatches(%q, %q) = %v, want %v", tc.version, tc.constraint, got, tc.want)
		}
	}
}

func TestCompositionDigestBindsImmutableInputs(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	// Keep this test focused on identity: graph capability transitions are
	// covered separately, while each listed field remains semantically valid.
	m.Requires = Requires{Exports: []ExportRequirement{}, Capabilities: []Capability{}}
	m.Provides = []ProvidedCapability{{Name: "runtime", Value: "next-app", RuleID: "identity.rule"}}
	m.Conflicts = []Capability{}
	m.Replaces = []Replacement{}
	m.Bindings = []Binding{{Name: "first", Value: json.RawMessage(`"one"`)}, {Name: "second", Value: json.RawMessage(`true`)}}
	m.Rules = []Operation{{ID: "identity.rule", Op: "add", Export: "next.block.identity", Before: []string{}, After: []string{}}}
	resolve := func(candidate Modifier) Composition {
		t.Helper()
		got, err := ResolveModifiers(RuleSet{}, []Modifier{candidate})
		if err != nil {
			t.Fatalf("%v: %+v", err, candidate)
		}
		return got
	}
	got := resolve(m)
	const golden = "sha256:e334e1b42949d7466aad52e884a75b7a37c899bfa3b922ce69c5101d12d648ee"
	if got.Digest != golden {
		t.Fatalf("composition digest = %s, want %s", got.Digest, golden)
	}
	for name, mutate := range map[string]func(*Modifier){
		"source pin": func(x *Modifier) { x.Sources[0].Commit = strings.Repeat("1", 40) },
		"export":     func(x *Modifier) { x.Rules[0].Export = "next.block.changed" },
		"binding":    func(x *Modifier) { x.Bindings[0].Value = json.RawMessage(`"changed"`) },
		"capability": func(x *Modifier) { x.Provides[0].Value = "changed-runtime" },
		"tool": func(x *Modifier) {
			x.ToolConstraints = []ToolConstraint{{ID: "formatter", CompatibleRange: "*", OptionsDigest: "sha256:" + zeros}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneModifierForTest(m)
			mutate(&changed)
			if name == "tool" {
				// Tool facts are a verified pure input and therefore participate
				// in the composition digest as well as validation.
				candidate, err := ResolveModifiers(RuleSet{Tools: map[string]ToolFact{"formatter": {Version: "1.0.0", OptionsDigest: "sha256:" + zeros}}}, []Modifier{changed})
				if err != nil {
					t.Fatal(err)
				}
				if candidate.Digest == got.Digest || candidate.Rules[0].Digest == got.Rules[0].Digest {
					t.Fatal("changed tool identity preserved digest")
				}
				return
			}
			if candidate := resolve(changed); candidate.Digest == got.Digest || candidate.Rules[0].Digest == got.Rules[0].Digest {
				t.Fatal("changed immutable input preserved identity")
			}
		})
	}
	reordered := cloneModifierForTest(m)
	reordered.Sources[0], reordered.Sources[1] = reordered.Sources[1], reordered.Sources[0]
	reordered.Bindings[0], reordered.Bindings[1] = reordered.Bindings[1], reordered.Bindings[0]
	if candidate := resolve(reordered); candidate.Digest != got.Digest || candidate.Rules[0].Digest != got.Rules[0].Digest {
		t.Fatalf("normalized equivalent input changed identity: %#v", candidate)
	}
}

func TestCompositionOwnsNestedValues(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Requires = Requires{Exports: []ExportRequirement{{Selector: "react.approach.runtime", ContractDigest: "sha256:" + zeros, CompatibleRange: "*"}}, Capabilities: []Capability{}}
	m.Provides = []ProvidedCapability{{Name: "runtime", Value: "next-app", RuleID: "owned.rule"}}
	m.Conflicts, m.Replaces = []Capability{}, []Replacement{}
	m.Bindings = []Binding{{Name: "value", Value: json.RawMessage(`"original"`)}}
	m.ToolConstraints = []ToolConstraint{{ID: "formatter", CompatibleRange: "*", OptionsDigest: "sha256:" + zeros}}
	m.Rules = []Operation{{ID: "owned.rule", Op: "add", Export: "next.block.owned", Before: []string{"x"}, After: []string{}}}
	// The edge is invalid alone; use a second operation to make it meaningful.
	m.Rules = append(m.Rules, Operation{ID: "x", Op: "add", Export: "next.block.x", Before: []string{}, After: []string{}})
	base := RuleSet{Exports: map[string]ExportFact{"react.approach.runtime": {ContractDigest: "sha256:" + zeros, Version: "1.0.0"}}, Tools: map[string]ToolFact{"formatter": {Version: "1.0.0", OptionsDigest: "sha256:" + zeros}}}
	c, err := ResolveModifiers(base, []Modifier{m})
	if err != nil {
		t.Fatal(err)
	}
	original := c.Digest
	// Output-to-input mutations must not cross the boundary.
	c.Rules[0].Sources[0].Origin = "https://changed.invalid/repo"
	c.Rules[0].Bindings[0].Value[1] = 'X'
	c.Rules[0].Operation.Before[0] = "changed"
	c.Rules[0].ExportFacts["react.approach.runtime"] = ExportFact{Version: "changed"}
	c.Rules[0].ToolFacts["formatter"] = ToolFact{Version: "changed"}
	c.Ordered[0].Before = append(c.Ordered[0].Before, "changed")
	if m.Sources[0].Origin == "https://changed.invalid/repo" || string(m.Bindings[0].Value) != `"original"` || m.Rules[0].Before[0] != "x" || base.Exports["react.approach.runtime"].Version == "changed" || base.Tools["formatter"].Version == "changed" {
		t.Fatal("composition output aliases modifier input")
	}
	// Input-to-output mutations after sealing must not alter the returned plan.
	m.Sources[0].Origin = "https://mutated.invalid/repo"
	m.Bindings[0].Value[1] = 'Y'
	m.Rules[0].Before[0] = "mutated"
	base.Exports["react.approach.runtime"] = ExportFact{Version: "mutated"}
	base.Tools["formatter"] = ToolFact{Version: "mutated"}
	if c.Digest != original || c.Rules[0].Sources[0].Origin == m.Sources[0].Origin || string(c.Rules[0].Bindings[0].Value) == string(m.Bindings[0].Value) || c.Rules[0].ExportFacts["react.approach.runtime"].Version == "mutated" || c.Rules[0].ToolFacts["formatter"].Version == "mutated" {
		t.Fatal("modifier input aliases composition output")
	}
}

func TestOperationEdgeSetIdentityNormalization(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "modifier", "next.synthetic.json"))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Requires = Requires{Exports: []ExportRequirement{}, Capabilities: []Capability{}}
	m.Provides, m.Conflicts, m.Replaces = []ProvidedCapability{}, []Capability{}, []Replacement{}
	m.Rules = []Operation{
		{ID: "a", Op: "add", Export: "next.block.a", Before: []string{"b", "c"}, After: []string{}},
		{ID: "b", Op: "add", Export: "next.block.b", Before: []string{}, After: []string{}},
		{ID: "c", Op: "add", Export: "next.block.c", Before: []string{}, After: []string{}},
	}
	resolve := func(candidate Modifier) Composition {
		t.Helper()
		out, err := ResolveModifiers(RuleSet{}, []Modifier{candidate})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	firstRule, err := ruleFor(operationRef{m: m, op: m.Rules[0]}, RuleSet{})
	if err != nil {
		t.Fatal(err)
	}
	first := resolve(m)
	permuted := cloneModifierForTest(m)
	permuted.Rules[0].Before = []string{"c", "b"}
	permutedRule, err := ruleFor(operationRef{m: permuted, op: permuted.Rules[0]}, RuleSet{})
	if err != nil {
		t.Fatal(err)
	}
	second := resolve(permuted)
	if firstRule.Digest != permutedRule.Digest || first.Digest != second.Digest {
		t.Fatalf("edge-set permutation changed identity: rule %s/%s composition %s/%s", firstRule.Digest, permutedRule.Digest, first.Digest, second.Digest)
	}
	changed := cloneModifierForTest(m)
	changed.Rules[0].Before = []string{"b"}
	if candidate := resolve(changed); candidate.Digest == first.Digest {
		t.Fatal("semantic edge change preserved composition identity")
	}
}

func cloneModifierForTest(m Modifier) Modifier {
	return normalizedModifier(m)
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"
