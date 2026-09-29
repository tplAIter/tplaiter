package blockformatter

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func tsProvider() TypeScriptProvider {
	d := "sha256:" + strings.Repeat("0", 64)
	return TypeScriptProvider{APIVersion: TypeScriptProviderAPIVersion, Adapter: TypeScriptAdapterID, PrettierVersion: "3.9.6", CompilerVersion: "6.0.3", EstreeVersion: "8.65.0", CommentUtilsVersion: "2.5.0", NodeVersion: "26.9.0", NodeBinarySHA256: d, Files: []TypeScriptProviderFile{{"adapter/typescript.cjs", "100644", d}, {"tool/plugins/estree.cjs", "100644", d}, {"tool/plugins/typescript.cjs", "100644", d}, {"tool/standalone.cjs", "100644", d}}, FormatOptions: TypeScriptFormatOptions{Parser: "typescript", PrintWidth: 80, TabWidth: 2, Semi: true, QuoteProps: "as-needed", TrailingComma: "all", BracketSpacing: true, ArrowParens: "always", EndOfLine: "lf", EmbeddedLanguageFormatting: "off", ProseWrap: "preserve"}}
}

func TestTypeScriptProviderFixedDescriptor(t *testing.T) {
	p := tsProvider()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Files[0].Path = "tool/evil.cjs"
	if p.Validate() == nil {
		t.Fatal("accepted caller path")
	}
}

func TestTypeScriptHelperIsFixedAndNotRunner(t *testing.T) {
	s := string(TypeScriptHelperBytes())
	for _, want := range []string{"standalone.cjs", "typescript.cjs", "estree.cjs", "validate", "format"} {
		if !strings.Contains(s, want) {
			t.Fatalf("helper missing %q", want)
		}
	}
	for _, bad := range []string{"child_process", "resolveConfig", "require(\"prettier\")"} {
		if strings.Contains(s, bad) {
			t.Fatalf("helper has forbidden %q", bad)
		}
	}
	first := TypeScriptHelperBytes()
	digest := TypeScriptHelperSHA256()
	if len(first) == 0 || bytes.Equal(first, []byte("")) {
		t.Fatal("missing embedded helper")
	}
	first[0] ^= 0xff
	if bytes.Equal(first, TypeScriptHelperBytes()) || TypeScriptHelperSHA256() != digest {
		t.Fatal("helper bytes are not isolated from caller mutation")
	}
	if _, err := os.ReadFile("../../schema/typescript-provider.v1.schema.json"); err != nil {
		t.Fatal(err)
	}
}

func TestTypeScriptRequestLanguageAndPathContract(t *testing.T) {
	valid := []struct{ language, path string }{{"typescript", "src/input.ts"}, {"typescript", "src/input.mts"}, {"typescript", "src/input.cts"}, {"tsx", "src/view.tsx"}}
	for _, tc := range valid {
		if err := ValidateTypeScriptRequest(tc.language, tc.path); err != nil {
			t.Errorf("valid request %q/%q: %v", tc.language, tc.path, err)
		}
	}
	invalid := []struct{ language, path string }{{"tsx", "src/input.ts"}, {"typescript", "src/view.tsx"}, {"typescript", "/tmp/input.ts"}, {"typescript", "../input.ts"}, {"typescript", "src/../input.ts"}, {"typescript", "src\\input.ts"}, {"typescript", "input"}}
	for _, tc := range invalid {
		if ValidateTypeScriptRequest(tc.language, tc.path) == nil {
			t.Errorf("accepted invalid request %q/%q", tc.language, tc.path)
		}
	}
	for _, n := range []int{1021, 1022} {
		path := strings.Repeat("a", n) + ".ts"
		err := ValidateTypeScriptRequest("typescript", path)
		if (n == 1021 && err != nil) || (n == 1022 && err == nil) {
			t.Errorf("ASCII boundary n=%d: %v", n, err)
		}
	}
	if ValidateTypeScriptRequest("typescript", strings.Repeat("a", 4094)+".ts") == nil {
		t.Fatal("over-byte-bound ASCII path accepted")
	}
	if ValidateTypeScriptRequest("typescript", strings.Repeat("😀", 1024)+".ts") == nil {
		t.Fatal("non-ASCII path over codepoint bound accepted")
	}
}

func TestTypeScriptSchemaIsClosedAndMatchesDescriptor(t *testing.T) {
	b, err := os.ReadFile("../../schema/typescript-provider.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatal("schema is not closed")
	}
	props := schema["properties"].(map[string]any)
	files := props["files"].(map[string]any)
	if files["items"] != false || len(files["prefixItems"].([]any)) != 4 {
		t.Fatal("schema does not close ordered provider files")
	}
	format := props["formatOptions"].(map[string]any)["$ref"]
	if format != "#/$defs/formatOptions" {
		t.Fatalf("unexpected format options schema: %v", format)
	}
	defs := schema["$defs"].(map[string]any)["formatOptions"].(map[string]any)
	if defs["additionalProperties"] != false || len(defs["required"].([]any)) != 17 {
		t.Fatal("format options are not closed")
	}
}

func TestTypeScriptProviderWireUsesSchemaNames(t *testing.T) {
	b, err := json.Marshal(tsProvider())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"apiVersion", "adapter", "prettierVersion", "compilerVersion", "estreeVersion", "commentUtilsVersion", "nodeVersion", "nodeBinarySHA256", "files", "formatOptions"} {
		if _, ok := wire[key]; !ok {
			t.Fatalf("missing schema field %q", key)
		}
	}
	if _, ok := wire["APIVersion"]; ok {
		t.Fatal("Go field name leaked into provider wire")
	}
}

func canonicalProviderWire(t *testing.T) []byte {
	t.Helper()
	structured, err := json.Marshal(tsProvider())
	if err != nil {
		t.Fatal(err)
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(structured))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestDecodeTypeScriptProviderStrictWire(t *testing.T) {
	valid := canonicalProviderWire(t)
	if _, err := DecodeTypeScriptProvider(valid); err != nil {
		t.Fatalf("valid canonical descriptor rejected: %v", err)
	}
	cases := [][]byte{
		append([]byte{0xef, 0xbb, 0xbf}, valid...),
		append(append([]byte{}, valid...), []byte(" ")...),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-provider/v1","apiVersion":"tplaiter.dev/typescript-provider/v1"}`),
	}
	for i, raw := range cases {
		if _, err := DecodeTypeScriptProvider(raw); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	var wire map[string]any
	if err := json.Unmarshal(valid, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"apiVersion", "adapter", "prettierVersion", "compilerVersion", "estreeVersion", "commentUtilsVersion", "nodeVersion", "nodeBinarySHA256", "files", "formatOptions"} {
		missing := make(map[string]any, len(wire)-1)
		for k, v := range wire {
			if k != key {
				missing[k] = v
			}
		}
		mutated, _ := json.Marshal(missing)
		if _, err := DecodeTypeScriptProvider(mutated); err == nil {
			t.Errorf("missing %s accepted", key)
		}
		nulled := make(map[string]any, len(wire))
		for k, v := range wire {
			nulled[k] = v
		}
		nulled[key] = nil
		mutated, _ = json.Marshal(nulled)
		if _, err := DecodeTypeScriptProvider(mutated); err == nil {
			t.Errorf("null %s accepted", key)
		}
	}
	unknown := make(map[string]any, len(wire)+1)
	for k, v := range wire {
		unknown[k] = v
	}
	unknown["unknown"] = true
	mutated, _ := json.Marshal(unknown)
	if _, err := DecodeTypeScriptProvider(mutated); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	options := wire["formatOptions"].(map[string]any)
	options["semi"] = 1
	mutated, _ = json.Marshal(wire)
	if _, err := DecodeTypeScriptProvider(mutated); err == nil {
		t.Fatal("boolean scalar substitution accepted")
	}
	files := wire["files"].([]any)
	files[0].(map[string]any)["unknown"] = true
	mutated, _ = json.Marshal(wire)
	if _, err := DecodeTypeScriptProvider(mutated); err == nil {
		t.Fatal("unknown file field accepted")
	}
}

func TestTypeScriptHelperSourceHasBoundedOriginalByteChecks(t *testing.T) {
	s := string(TypeScriptHelperBytes())
	for _, required := range []string{"MAX_INPUT_BYTES", "TextDecoder", "fatal: true", "65536", "previousEnd", "sha256(rawInput)", "Buffer.byteLength(logicalPath, 'utf8') > 4096", "Array.from(logicalPath).length > 1024"} {
		if !strings.Contains(s, required) {
			t.Errorf("helper missing %q", required)
		}
	}
	if strings.Index(s, "ast.comments.length > 65536") > strings.Index(s, "ast.comments.map") {
		t.Fatal("comment cap occurs after derived map allocation")
	}
}
