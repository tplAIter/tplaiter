package blockformatter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type fakeValidator struct {
	markers []Marker
	err     error
	calls   int
}

func (f *fakeValidator) Validate(string, string, []byte) ([]Marker, error) {
	f.calls++
	return append([]Marker(nil), f.markers...), f.err
}

func formatterTool(t *testing.T, opts []string) trustverify.Tool {
	t.Helper()
	d, err := trustverify.ComputeToolOptionsSHA256(opts)
	if err != nil {
		t.Fatal(err)
	}
	return trustverify.Tool{ID: "gofmt", Version: "1.26.0", BinarySHA256: "sha256:" + strings.Repeat("1", 64), OptionsSHA256: d}
}

func formatterInput(t *testing.T) PlanInput {
	return PlanInput{Path: "main.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: formatterTool(t, []string{}), Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 10000, OutputLimitBytes: 1 << 20, Input: []byte("package main\n")}
}

func TestD4BuildPlanParsePlanAndCanonicalGolden(t *testing.T) {
	p, err := BuildPlan(formatterInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.InputSHA256 != "sha256:df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47" {
		t.Fatalf("input digest=%s", p.InputSHA256)
	}
	raw := mustCanonical(p)
	parsed, err := ParsePlan(raw)
	if err != nil || parsed.PlanSHA256 != p.PlanSHA256 {
		t.Fatalf("parse=%#v err=%v", parsed, err)
	}
	if _, err := ParsePlan([]byte(strings.Replace(string(raw), `"path":"main.go"`, `"path":"main.go","path":"other.go"`, 1))); err == nil {
		t.Fatal("duplicate field accepted")
	}
	if _, err := ParsePlan(append(raw, 'x')); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestD4PlanLiteralVector(t *testing.T) {
	raw := []byte(`{"adapter":"gofmt-stdin-v1","apiVersion":"tplaiter.dev/formatter-plan/v1","inputMode":"100644","inputSHA256":"sha256:0ad6261536f6380b14ade1a508ac911b8c48230731746e0c76abd26bf3e3a15d","language":"go","markers":[],"options":[],"outputLimitBytes":1048576,"path":"main.go","planSHA256":"sha256:db02989362c68f6a13a29993ab2115909f8d4151b51776a8af1f0861c72186dd","timeoutMillis":10000,"tool":{"binarySHA256":"sha256:7ea3e750965f2bef35c1f3401c7fc8ba7480d57e7cd72019ca6f81411bf1fa22","id":"gofmt","optionsSHA256":"sha256:736a9ccd08e62223e9af15b1195ccd41984f242a48bf781c8be0259359a73543","version":"1.26.0"}}`)
	if _, err := ParsePlan(raw); err != nil {
		t.Fatalf("FORMAT-PLAN-1: %v", err)
	}
}

func TestD4CheckOutputsSameInputTwiceAndCopies(t *testing.T) {
	p, err := BuildPlan(formatterInput(t))
	if err != nil {
		t.Fatal(err)
	}
	v := &fakeValidator{}
	first := []byte("package main\n")
	check, err := CheckOutputs(p, formatterInput(t).Input, first, append([]byte(nil), first...), v)
	if err != nil || v.calls != 3 || !bytes.Equal(check.Formatted, first) || check.FirstOutputSHA256 != check.SecondOutputSHA256 {
		t.Fatalf("check=%#v err=%v calls=%d", check, err, v.calls)
	}
	check.Formatted[0] = 'x'
	if first[0] != 'p' {
		t.Fatal("formatted output aliases input")
	}
	if _, err := CheckOutputs(p, formatterInput(t).Input, first, []byte("different"), v); err == nil || materialCode(err) != "FORMAT_NONDETERMINISTIC" {
		t.Fatalf("nondeterminism=%v", err)
	}
}

func TestD4CheckOutputsMarkerAndSyntaxGates(t *testing.T) {
	in := formatterInput(t)
	in.Markers = []Marker{{Kind: "begin", ID: "a", Provider: "p"}, {Kind: "end", ID: "a", Provider: ""}}
	p, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	good := &fakeValidator{markers: append([]Marker(nil), in.Markers...)}
	if _, err := CheckOutputs(p, in.Input, in.Input, in.Input, good); err != nil {
		t.Fatal(err)
	}
	bad := &fakeValidator{markers: []Marker{{Kind: "begin", ID: "b", Provider: "p"}}}
	if _, err := CheckOutputs(p, in.Input, in.Input, in.Input, bad); err == nil || materialCode(err) != "FORMAT_MARKER" {
		t.Fatalf("marker=%v", err)
	}
	if _, err := CheckOutputs(p, in.Input, in.Input, in.Input, &fakeValidator{err: errSyntax{}}); err == nil || materialCode(err) != "FORMAT_SYNTAX" {
		t.Fatalf("syntax=%v", err)
	}
}

type errSyntax struct{}

func (errSyntax) Error() string { return "syntax" }
func materialCode(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return err.Error()
}

func TestD4ValidateMaterialToolsAllConstraints(t *testing.T) {
	tool := formatterTool(t, []string{})
	good := []exports.ToolConstraint{{ID: "gofmt", CompatibleRange: ">=1.25.0", OptionsDigest: tool.OptionsSHA256}, {ID: "gofmt", CompatibleRange: "<1.27.0", OptionsDigest: tool.OptionsSHA256}}
	if err := ValidateMaterialTools(good, []trustverify.Tool{tool}); err != nil {
		t.Fatal(err)
	}
	for _, constraints := range [][]exports.ToolConstraint{{{ID: "missing", CompatibleRange: "*", OptionsDigest: tool.OptionsSHA256}}, {{ID: "gofmt", CompatibleRange: ">1.27.0", OptionsDigest: tool.OptionsSHA256}}, {{ID: "gofmt", CompatibleRange: "*", OptionsDigest: "sha256:" + strings.Repeat("2", 64)}}} {
		if err := ValidateMaterialTools(constraints, []trustverify.Tool{tool}); err == nil || materialCode(err) != "FORMAT_TOOL_REQUIREMENT" {
			t.Fatalf("accepted constraint: %v", err)
		}
	}
	conflict := tool
	conflict.Version = "1.27.0"
	if err := ValidateMaterialTools(nil, []trustverify.Tool{tool, conflict}); err == nil {
		t.Fatal("conflicting duplicate actual pin accepted")
	}
}

func TestD4PlanBoundsModesAdaptersAndDefensiveCopies(t *testing.T) {
	for _, mutate := range []func(*PlanInput){func(in *PlanInput) { in.Path = "/main.go" }, func(in *PlanInput) { in.InputMode = "100777" }, func(in *PlanInput) { in.TimeoutMillis = 0 }, func(in *PlanInput) { in.OutputLimitBytes = maxOutputBytes + 1 }, func(in *PlanInput) { in.Adapter = "gofmt" }} {
		in := formatterInput(t)
		mutate(&in)
		if _, err := BuildPlan(in); err == nil {
			t.Fatal("invalid plan accepted")
		}
	}
	in := formatterInput(t)
	p, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Options = append(in.Options, "x")
	in.Markers = append(in.Markers, Marker{Kind: "begin", ID: "a", Provider: "p"})
	if len(p.Options) != 0 || len(p.Markers) != 0 {
		t.Fatal("plan aliases inputs")
	}
}

func TestD4PlanWireStrictAndSchemaOracle(t *testing.T) {
	raw, err := os.ReadFile("../../schema/formatter-plan.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	uri := "https://schemas.invalid/formatter-plan.v1.schema.json"
	if err := c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(formatterInput(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := mustCanonical(p)
	value, err := js.UnmarshalJSON(strings.NewReader(string(canonical)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(value); err != nil {
		t.Fatalf("valid plan rejected by schema: %v", err)
	}
	bad := []string{
		strings.Replace(string(canonical), `"path":"main.go"`, `"path":"main.go","unknown":true`, 1),
		strings.Replace(string(canonical), `"timeoutMillis":10000`, `"timeoutMillis":0`, 1),
		strings.Replace(string(canonical), `"adapter":"gofmt-stdin-v1"`, `"adapter":"prettier-anything"`, 1),
		strings.Replace(string(canonical), `"options":[]`, `"options":null`, 1),
	}
	for i, candidate := range bad {
		value, err := js.UnmarshalJSON(strings.NewReader(candidate))
		if err != nil {
			t.Fatalf("negative schema fixture %d decode: %v", i, err)
		}
		if err := s.Validate(value); err == nil {
			t.Fatalf("negative schema fixture %d accepted", i)
		}
		if _, err := ParsePlan([]byte(candidate)); err == nil {
			t.Fatalf("strict wire case %d accepted", i)
		}
	}
}

func TestD4FormatPlanLiteralAndMutationDomains(t *testing.T) {
	p, err := BuildPlan(formatterInput(t))
	if err != nil {
		t.Fatal(err)
	}
	base := p.PlanSHA256
	mutations := []func(*Plan){
		func(x *Plan) { x.Path = "other.go" }, func(x *Plan) { x.InputMode = "100755" },
		func(x *Plan) { x.TimeoutMillis++ }, func(x *Plan) { x.OutputLimitBytes++ },
		func(x *Plan) { x.Tool.ID = "other" }, func(x *Plan) { x.Options = []string{"x"} },
	}
	for i, mutate := range mutations {
		q := clonePlan(p)
		mutate(&q)
		d, e := planDigest(q)
		if e != nil || d == base {
			t.Fatalf("mutation %d did not change domain: %v", i, e)
		}
	}
}

func TestD4FixedAdapterLanguageOptions(t *testing.T) {
	valid := []struct {
		language, adapter string
		options           []string
	}{
		{"go", "gofmt-stdin-v1", nil},
		{"rust", "rustfmt-stdin-v1", []string{"--emit", "stdout", "--edition", "2021", "--config-path", "formatter/rustfmt.toml"}},
		{"typescript", TypeScriptAdapterID, nil},
		{"tsx", TypeScriptAdapterID, nil},
	}
	for _, tc := range valid {
		if !adapterAllowed(tc.language, tc.adapter, tc.options) {
			t.Fatalf("valid adapter rejected: %#v", tc)
		}
	}
	for _, tc := range []struct {
		language, adapter string
		options           []string
	}{{"typescript", "prettier-anything", nil}, {"go", "gofmt-stdin-v1", []string{"--x"}}, {"rust", "rustfmt-stdin-v1", nil}} {
		if adapterAllowed(tc.language, tc.adapter, tc.options) {
			t.Fatalf("invalid adapter accepted: %#v", tc)
		}
	}
	in := formatterInput(t)
	in.Tool.ID = "rustfmt"
	if _, err := BuildPlan(in); err == nil {
		t.Fatal("gofmt adapter accepted rustfmt tool")
	}
}

func TestD4ToolPinsAndExistingRangeGrammar(t *testing.T) {
	tool := formatterTool(t, nil)
	if err := ValidateMaterialTools([]exports.ToolConstraint{{ID: tool.ID, CompatibleRange: ">=1.25.0", OptionsDigest: tool.OptionsSHA256}}, []trustverify.Tool{tool}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.2.3-01", "1.2", "v1.2.3"} {
		bad := tool
		bad.Version = version
		if err := ValidateMaterialTools(nil, []trustverify.Tool{bad}); err == nil {
			t.Fatalf("invalid version accepted: %s", version)
		}
	}
	for _, version := range []string{"1", "1.2.3-01"} {
		in := formatterInput(t)
		in.Tool.Version = version
		if _, err := BuildPlan(in); err == nil {
			t.Fatalf("BuildPlan accepted invalid version: %s", version)
		}
	}
	in := formatterInput(t)
	in.Tool.Version = "1.2.3+build.7"
	if _, err := BuildPlan(in); err != nil {
		t.Fatalf("BuildPlan rejected valid metadata version: %v", err)
	}
}

func TestD4CheckOutputsSameInputAndFailureMatrix(t *testing.T) {
	in := formatterInput(t)
	p, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckOutputs(p, in.Input, in.Input, in.Input, nil); materialCode(err) != "FORMAT_UNAVAILABLE" {
		t.Fatalf("nil validator: %v", err)
	}
	if _, err := CheckOutputs(p, in.Input, in.Input, []byte("different"), &fakeValidator{}); materialCode(err) != "FORMAT_NONDETERMINISTIC" {
		t.Fatalf("non-idempotent: %v", err)
	}
	if _, err := CheckOutputs(p, []byte("wrong\n"), in.Input, in.Input, &fakeValidator{}); materialCode(err) != "FORMAT_PLAN" {
		t.Fatalf("wrong input: %v", err)
	}
	if _, err := CheckOutputs(p, in.Input, in.Input, in.Input, &fakeValidator{err: errSyntax{}}); materialCode(err) != "FORMAT_SYNTAX" {
		t.Fatalf("syntax: %v", err)
	}
}

func TestD4SchemaClosedFieldOraclePairedBoundaries(t *testing.T) {
	p, err := BuildPlan(formatterInput(t))
	if err != nil {
		t.Fatal(err)
	}
	base := mustCanonical(p)
	raw, err := os.ReadFile("../../schema/formatter-plan.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	uri := "https://schemas.invalid/formatter-plan.v1.schema.json"
	if err := c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	valid := func(name, candidate string) {
		t.Helper()
		value, e := js.UnmarshalJSON(strings.NewReader(candidate))
		if e != nil {
			t.Fatalf("%s decode: %v", name, e)
		}
		if e = s.Validate(value); e != nil {
			t.Fatalf("%s schema: %v", name, e)
		}
		if _, e = ParsePlan([]byte(candidate)); e != nil {
			t.Fatalf("%s parser: %v", name, e)
		}
	}
	valid("base", string(base))
	negatives := []struct{ name, needle, replacement string }{
		{"missing-tool-version", `"id":"gofmt",`, ``},
		{"null-tool", `"tool":{`, `"tool":null,`},
		{"unknown-tool", `"tool":{"`, `"tool":{"unknown":true,"`},
		{"null-options", `"options":[],`, `"options":null,`},
		{"wrong-options-type", `"options":[],`, `"options":{},`},
		{"null-markers", `"markers":[],`, `"markers":null,`},
		{"wrong-marker-type", `"markers":[],`, `"markers":{},`},
		{"unknown-marker", `"markers":[],`, `"markers":[{"unknown":true}],`},
		{"wrong-marker-provider", `"markers":[],`, `"markers":[{"kind":"end","id":"a","provider":1}],`},
		{"wrong-timeout-type", `"timeoutMillis":10000,`, `"timeoutMillis":1.5,`},
		{"output-over-bound", `"outputLimitBytes":1048576,`, `"outputLimitBytes":16777217,`},
		{"options-over-cardinality", `"options":[],`, `"options":[` + strings.Repeat(`"x",`, 256) + `"x"],`},
	}
	for _, tc := range negatives {
		candidate := strings.Replace(string(base), tc.needle, tc.replacement, 1)
		if tc.name == "null-tool" {
			var object map[string]any
			if err := json.Unmarshal(base, &object); err != nil {
				t.Fatal(err)
			}
			object["tool"] = nil
			candidateBytes, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			candidate = string(candidateBytes)
		}
		if candidate == string(base) {
			t.Fatalf("negative %s did not mutate fixture", tc.name)
		}
		value, e := js.UnmarshalJSON(strings.NewReader(candidate))
		if e != nil {
			t.Fatalf("%s decode: %v", tc.name, e)
		}
		if e = s.Validate(value); e == nil {
			t.Fatalf("%s schema accepted", tc.name)
		}
		if _, e = ParsePlan([]byte(candidate)); e == nil {
			t.Fatalf("%s parser accepted", tc.name)
		}
	}
	for _, limit := range []int64{1, 120000, 16777216} {
		in := formatterInput(t)
		in.TimeoutMillis = limit
		in.OutputLimitBytes = limit
		if limit == 16777216 {
			in.TimeoutMillis = 120000
		}
		q, e := BuildPlan(in)
		if e != nil {
			t.Fatalf("boundary %d: %v", limit, e)
		}
		value, e := js.UnmarshalJSON(strings.NewReader(string(mustCanonical(q))))
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Validate(value); e != nil {
			t.Fatalf("boundary %d schema: %v", limit, e)
		}
	}
}

func TestD4FormatPlanAllDomainMutationsAndExactBounds(t *testing.T) {
	in := formatterInput(t)
	p, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	base, err := planDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Plan){
		func(x *Plan) { x.InputSHA256 = digest([]byte("other")) },
		func(x *Plan) { x.Tool.Version = "1.26.1" },
		func(x *Plan) { x.Tool.BinarySHA256 = "sha256:" + strings.Repeat("3", 64) },
		func(x *Plan) { x.Tool.OptionsSHA256 = "sha256:" + strings.Repeat("4", 64) },
		func(x *Plan) { x.Markers = []Marker{{Kind: "begin", ID: "a", Provider: "p"}} },
		func(x *Plan) { x.Markers = []Marker{{Kind: "end", ID: "a"}} },
		func(x *Plan) { x.Options = []string{"x", "y"} },
		func(x *Plan) { x.Options = []string{"y", "x"} },
	}
	for i, mutate := range mutations {
		q := clonePlan(p)
		mutate(&q)
		d, e := planDigest(q)
		if e != nil || d == base {
			t.Fatalf("mutation %d unchanged: %v", i, e)
		}
	}
	for _, version := range []string{"1.2.3-alpha.1", "1.2.3+build.7"} {
		q := in
		q.Tool.Version = version
		if _, err := BuildPlan(q); err != nil {
			t.Fatalf("valid version %s: %v", version, err)
		}
	}
	tool := formatterTool(t, nil)
	for _, constraint := range []string{"*", ">=1.26.0 <1.27.0"} {
		if err := ValidateMaterialTools([]exports.ToolConstraint{{ID: tool.ID, CompatibleRange: constraint, OptionsDigest: tool.OptionsSHA256}}, []trustverify.Tool{tool}); err != nil {
			t.Fatalf("constraint %s: %v", constraint, err)
		}
	}
	for _, constraint := range []string{"", "latest", ">>1.0.0", ">=1.26.0 || <1.0.0"} {
		if err := ValidateMaterialTools([]exports.ToolConstraint{{ID: tool.ID, CompatibleRange: constraint, OptionsDigest: tool.OptionsSHA256}}, []trustverify.Tool{tool}); err == nil {
			t.Fatalf("unsupported constraint accepted: %s", constraint)
		}
	}
	in.OutputLimitBytes = 1
	p, err = BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckOutputs(p, in.Input, []byte("x"), []byte("x"), &fakeValidator{}); err != nil {
		t.Fatalf("exact output bound: %v", err)
	}
	if _, err := CheckOutputs(p, in.Input, []byte("xx"), []byte("xx"), &fakeValidator{}); materialCode(err) != "FORMAT_OUTPUT_LIMIT" {
		t.Fatalf("output +1: %v", err)
	}
	if _, err := BuildPlan(PlanInput{Path: "main.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: formatterTool(t, []string{}), Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 10000, OutputLimitBytes: maxOutputBytes, Input: bytes.Repeat([]byte{'x'}, maxOutputBytes+1)}); materialCode(err) != "FORMAT_OUTPUT_LIMIT" {
		t.Fatalf("input +1: %T %v", err, err)
	}
}

// d4SchemaFixture returns an independently decoded object and the compiled
// shipped schema. Keeping the object as map[string]any makes each generated
// row a real wire mutation rather than a production validation call.
func d4SchemaFixture(t *testing.T) (map[string]any, *js.Schema, []byte) {
	t.Helper()
	in := formatterInput(t)
	in.Markers = []Marker{{Kind: "begin", ID: "a", Provider: "p"}}
	p, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../schema/formatter-plan.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	const uri = "https://schemas.invalid/formatter-plan.v1.schema.json"
	if err := c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	canonical := mustCanonical(p)
	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	return object, s, canonical
}

func d4CloneObject(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	if err := json.Unmarshal(b, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func d4WireNegative(t *testing.T, schema *js.Schema, name string, object map[string]any) {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("%s marshal: %v", name, err)
	}
	value, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("%s schema decode: %v", name, err)
	}
	if err := schema.Validate(value); err == nil {
		t.Fatalf("%s schema accepted", name)
	}
	if _, err := ParsePlan(raw); err == nil {
		t.Fatalf("%s ParsePlan accepted", name)
	}
}

func d4SetNested(t *testing.T, object map[string]any, path []string, value any) {
	t.Helper()
	var current any = object
	for _, key := range path[:len(path)-1] {
		m, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("nested path %v is not an object", path)
		}
		current = m[key]
	}
	m, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("nested path %v parent is not an object", path)
	}
	m[path[len(path)-1]] = value
}

func d4DeleteNested(t *testing.T, object map[string]any, path []string) {
	t.Helper()
	var current any = object
	for _, key := range path[:len(path)-1] {
		m, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("nested path %v is not an object", path)
		}
		current = m[key]
	}
	m, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("nested path %v parent is not an object", path)
	}
	delete(m, path[len(path)-1])
}

func d4RawDuplicate(t *testing.T, raw []byte, scope, key string) []byte {
	t.Helper()
	text := string(raw)
	start, end := 0, len(text)
	switch scope {
	case "tool":
		start = strings.Index(text, `"tool":{`)
		if start < 0 {
			t.Fatalf("tool scope missing")
		}
		end = strings.Index(text[start:], "}") + start
	case "marker":
		start = strings.Index(text, `"markers":[{`)
		if start < 0 {
			t.Fatalf("marker scope missing")
		}
		end = strings.Index(text[start:], "}") + start
	}
	needle := fmt.Sprintf(`"%s":`, key)
	pos := strings.Index(text[start:end], needle)
	if pos < 0 {
		t.Fatalf("%s.%s missing", scope, key)
	}
	pos += start
	valueStart := pos + len(needle)
	valueEnd := valueStart
	if text[valueStart] == '"' {
		valueEnd++
		for valueEnd < len(text) {
			if text[valueEnd] == '"' && text[valueEnd-1] != '\\' {
				valueEnd++
				break
			}
			valueEnd++
		}
	} else if text[valueStart] == '{' || text[valueStart] == '[' {
		open := text[valueStart]
		close := byte('}')
		if open == '[' {
			close = ']'
		}
		depth := 0
		inString := false
		for valueEnd < len(text) {
			switch text[valueEnd] {
			case '"':
				if valueEnd == valueStart || text[valueEnd-1] != '\\' {
					inString = !inString
				}
			case open:
				if !inString {
					depth++
				}
			case close:
				if !inString {
					depth--
					if depth == 0 {
						valueEnd++
						goto valueDone
					}
				}
			}
			valueEnd++
		}
	} else {
		for valueEnd < len(text) && text[valueEnd] != ',' && text[valueEnd] != '}' {
			valueEnd++
		}
	}
valueDone:
	return []byte(text[:valueEnd] + "," + text[pos:valueEnd] + text[valueEnd:])
}

func TestD4SchemaClosedFieldOracleGenerated(t *testing.T) {
	base, schema, canonical := d4SchemaFixture(t)
	type field struct {
		name, scope string
		path        []string
		wrong       any
	}
	fields := []field{
		{"top.apiVersion", "top", []string{"apiVersion"}, true},
		{"top.path", "top", []string{"path"}, 1},
		{"top.language", "top", []string{"language"}, true},
		{"top.adapter", "top", []string{"adapter"}, true},
		{"top.tool", "top", []string{"tool"}, true},
		{"top.options", "top", []string{"options"}, map[string]any{}},
		{"top.inputSHA256", "top", []string{"inputSHA256"}, true},
		{"top.inputMode", "top", []string{"inputMode"}, true},
		{"top.markers", "top", []string{"markers"}, map[string]any{}},
		{"top.timeoutMillis", "top", []string{"timeoutMillis"}, 1.5},
		{"top.outputLimitBytes", "top", []string{"outputLimitBytes"}, 1.5},
		{"top.planSHA256", "top", []string{"planSHA256"}, true},
		{"tool.id", "tool", []string{"tool", "id"}, true},
		{"tool.version", "tool", []string{"tool", "version"}, true},
		{"tool.binarySHA256", "tool", []string{"tool", "binarySHA256"}, true},
		{"tool.optionsSHA256", "tool", []string{"tool", "optionsSHA256"}, true},
		{"marker.kind", "marker", []string{"markers", "0", "kind"}, true},
		{"marker.id", "marker", []string{"markers", "0", "id"}, true},
		{"marker.provider", "marker", []string{"markers", "0", "provider"}, 1},
	}
	duplicateCount := 0
	for _, f := range fields {
		for _, mutation := range []struct {
			name string
			fn   func(map[string]any)
		}{
			{"missing", func(o map[string]any) {
				if f.scope == "marker" {
					markers := o["markers"].([]any)
					delete(markers[0].(map[string]any), f.path[2])
				} else if f.scope == "tool" {
					delete(o["tool"].(map[string]any), f.path[1])
				} else {
					delete(o, f.path[0])
				}
			}},
			{"null", func(o map[string]any) {
				if f.scope == "marker" {
					o["markers"].([]any)[0].(map[string]any)[f.path[2]] = nil
				} else if f.scope == "tool" {
					o["tool"].(map[string]any)[f.path[1]] = nil
				} else {
					o[f.path[0]] = nil
				}
			}},
			{"wrong-type", func(o map[string]any) {
				if f.scope == "marker" {
					o["markers"].([]any)[0].(map[string]any)[f.path[2]] = f.wrong
				} else if f.scope == "tool" {
					o["tool"].(map[string]any)[f.path[1]] = f.wrong
				} else {
					o[f.path[0]] = f.wrong
				}
			}},
		} {
			name := f.name + "." + mutation.name
			o := d4CloneObject(t, base)
			mutation.fn(o)
			if bytes.Equal(mustJSON(t, o), canonical) {
				t.Fatalf("%s did not mutate fixture", name)
			}
			d4WireNegative(t, schema, name, o)
		}
		duplicate := d4RawDuplicate(t, canonical, f.scope, func() string {
			if f.scope == "marker" {
				return f.path[2]
			}
			if f.scope == "tool" {
				return f.path[1]
			}
			return f.path[0]
		}())
		if _, err := ParsePlan(duplicate); err == nil {
			t.Fatalf("%s.duplicate ParsePlan accepted", f.name)
		}
		duplicateCount++
	}
	if got := len(fields) * 3; got != 57 {
		t.Fatalf("generated semantic count=%d, want 57", got)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"top.unknown", func(o map[string]any) { o["unknown"] = true }},
		{"tool.unknown", func(o map[string]any) { o["tool"].(map[string]any)["unknown"] = true }},
		{"marker.unknown", func(o map[string]any) { o["markers"].([]any)[0].(map[string]any)["unknown"] = true }},
	} {
		o := d4CloneObject(t, base)
		tc.mutate(o)
		d4WireNegative(t, schema, tc.name, o)
	}
	if duplicateCount != 19 {
		t.Fatalf("generated duplicate count=%d, want 19", duplicateCount)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestD4FormatPlanOrderAndPreimageDomains(t *testing.T) {
	first := formatterInput(t)
	first.Markers = []Marker{{Kind: "begin", ID: "a", Provider: "p"}, {Kind: "end", ID: "a"}, {Kind: "begin", ID: "b", Provider: "p"}, {Kind: "end", ID: "b"}}
	second := first
	second.Markers = []Marker{{Kind: "begin", ID: "b", Provider: "p"}, {Kind: "end", ID: "b"}, {Kind: "begin", ID: "a", Provider: "p"}, {Kind: "end", ID: "a"}}
	p1, err := BuildPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := BuildPlan(second)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := planDigest(p1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := planDigest(p2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 || bytes.Equal(mustCanonical(p1), mustCanonical(p2)) {
		t.Fatal("marker stream permutation collapsed")
	}

	rust := formatterInput(t)
	rust.Language, rust.Adapter = "rust", "rustfmt-stdin-v1"
	rust.Options = []string{"--emit", "stdout", "--edition", "2021", "--config-path", "formatter/rustfmt.toml"}
	rust.Tool.ID = "rustfmt"
	rust.Tool.OptionsSHA256, err = trustverify.ComputeToolOptionsSHA256(rust.Options)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := BuildPlan(rust)
	if err != nil {
		t.Fatal(err)
	}
	permuted := clonePlan(rp)
	permuted.Options = []string{"--config-path", "formatter/rustfmt.toml", "--edition", "2021", "--emit", "stdout"}
	permuted.Tool.OptionsSHA256, err = trustverify.ComputeToolOptionsSHA256(permuted.Options)
	if err != nil {
		t.Fatal(err)
	}
	rd1, err := planDigest(rp)
	if err != nil {
		t.Fatal(err)
	}
	rd2, err := planDigest(permuted)
	if err != nil {
		t.Fatal(err)
	}
	if rd1 == rd2 {
		t.Fatal("option list permutation collapsed")
	}

	mutations := []struct {
		name string
		fn   func(*Plan)
	}{
		{"apiVersion", func(p *Plan) { p.APIVersion = "other" }},
		{"path", func(p *Plan) { p.Path = "other.go" }},
		{"language", func(p *Plan) { p.Language = "rust" }},
		{"adapter", func(p *Plan) { p.Adapter = "other" }},
		{"tool.id", func(p *Plan) { p.Tool.ID = "other" }},
		{"tool.version", func(p *Plan) { p.Tool.Version = "1.26.1" }},
		{"tool.binarySHA256", func(p *Plan) { p.Tool.BinarySHA256 = "sha256:" + strings.Repeat("3", 64) }},
		{"tool.optionsSHA256", func(p *Plan) { p.Tool.OptionsSHA256 = "sha256:" + strings.Repeat("4", 64) }},
		{"options", func(p *Plan) { p.Options = []string{"changed"} }},
		{"inputSHA256", func(p *Plan) { p.InputSHA256 = digest([]byte("changed")) }},
		{"inputMode", func(p *Plan) { p.InputMode = "100755" }},
		{"markers", func(p *Plan) { p.Markers = []Marker{{Kind: "begin", ID: "x", Provider: "p"}} }},
		{"timeoutMillis", func(p *Plan) { p.TimeoutMillis++ }},
		{"outputLimitBytes", func(p *Plan) { p.OutputLimitBytes++ }},
	}
	for _, tc := range mutations {
		q := clonePlan(p1)
		tc.fn(&q)
		d, err := planDigest(q)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d == d1 {
			t.Fatalf("%s did not change digest", tc.name)
		}
	}
	q := clonePlan(p1)
	q.PlanSHA256 = digest([]byte("excluded"))
	qd, err := planDigest(q)
	if err != nil {
		t.Fatal(err)
	}
	if qd != d1 {
		t.Fatal("planSHA256 entered preimage")
	}
}

func TestD4RawOnlyWireRestrictions(t *testing.T) {
	_, _, canonical := d4SchemaFixture(t)
	duplicates := []struct {
		name string
		raw  []byte
	}{
		{"escaped-top-path", []byte(strings.Replace(string(canonical), `"path":"main.go"`, `"path":"main.go","pa\u0074h":"main.go"`, 1))},
		{"escaped-tool-id", []byte(strings.Replace(string(canonical), `"id":"gofmt"`, `"id":"gofmt","i\u0064":"gofmt"`, 1))},
		{"escaped-marker-kind", func() []byte {
			return []byte(strings.Replace(string(canonical), `"kind":"begin"`, `"kind":"begin","k\u0069nd":"begin"`, 1))
		}()},
	}
	for _, tc := range duplicates {
		if _, err := ParsePlan(tc.raw); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	for _, tc := range []struct {
		name          string
		needle, value string
	}{
		{"timeout-1.0", `"timeoutMillis":10000`, `"timeoutMillis":1.0`},
		{"timeout-1e0", `"timeoutMillis":10000`, `"timeoutMillis":1e0`},
		{"timeout-negative-zero", `"timeoutMillis":10000`, `"timeoutMillis":-0`},
		{"output-1.0", `"outputLimitBytes":1048576`, `"outputLimitBytes":1.0`},
		{"output-1e0", `"outputLimitBytes":1048576`, `"outputLimitBytes":1e0`},
		{"output-negative-zero", `"outputLimitBytes":1048576`, `"outputLimitBytes":-0`},
	} {
		raw := []byte(strings.Replace(string(canonical), tc.needle, tc.value, 1))
		if _, err := ParsePlan(raw); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	if _, err := ParsePlan(append([]byte("\xef\xbb\xbf"), canonical...)); err == nil {
		t.Fatal("BOM accepted")
	}
	invalidUTF8 := append([]byte(nil), canonical...)
	invalidUTF8[len(invalidUTF8)-1] = 0xff
	if _, err := ParsePlan(invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := ParsePlan(append(append([]byte(nil), canonical...), []byte(" {}")...)); err == nil {
		t.Fatal("trailing second value accepted")
	}
}
