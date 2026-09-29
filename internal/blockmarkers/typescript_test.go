package blockmarkers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

func tsDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func TestTypeScriptReportValidatesMarkersAndCopies(t *testing.T) {
	content := []byte("// tplater:managed-begin id=alpha provider=provider.one\nconst café = 1;\n// tplater:managed-end id=alpha\n")
	raw := TypeScriptReport{APIVersion: typeScriptReportAPI, Language: "typescript", Path: "input.ts", InputSHA256: tsDigest(content), ProviderSHA256: tsDigest([]byte("provider")), Comments: []TypeScriptComment{{Kind: "line", StartByte: 0, EndByte: 55}, {Kind: "line", StartByte: 73, EndByte: 104}}}
	wire, _ := json.Marshal(raw)
	parsed, err := ParseTypeScriptReport(wire)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := ValidateTypeScriptReport(parsed, raw.ProviderSHA256, content)
	if err != nil {
		t.Fatal(err)
	}
	if len(markers) != 2 || markers[0].ID != "alpha" || markers[0].Provider != "provider.one" || markers[1].Kind != KindEnd {
		t.Fatalf("unexpected markers: %#v", markers)
	}
	parsed.Comments[0].StartByte = 99
	if markers[0].Start != 0 {
		t.Fatal("returned marker was not independent")
	}
}

func TestTypeScriptReportRejectsWireAndBindingAttacks(t *testing.T) {
	content := []byte("// tplater:managed-begin id=a provider=p\n// tplater:managed-end id=a\n")
	valid := TypeScriptReport{APIVersion: typeScriptReportAPI, Language: "typescript", Path: "a.ts", InputSHA256: tsDigest(content), ProviderSHA256: tsDigest([]byte("p")), Comments: []TypeScriptComment{{Kind: "line", StartByte: 0, EndByte: 40}, {Kind: "line", StartByte: 41, EndByte: 68}}}
	base, _ := json.Marshal(valid)
	for _, bad := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":null,"providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":null}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":null,"startByte":0,"endByte":1}]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":"evil","startByte":0,"endByte":1}]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":"line","startByte":0,"endByte":1,"unknown":true}]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":"line","startByte":0}]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[],"comments":[]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":"line","startByte":-0,"endByte":1}]}`),
		[]byte(`{"apiVersion":"tplaiter.dev/typescript-comments/v1","language":"typescript","path":"a.ts","inputSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","providerSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","comments":[{"kind":"line","startByte":1.0,"endByte":1e0}]}`),
		append(append([]byte{}, base...), []byte("{}")...),
	} {
		if _, err := ParseTypeScriptReport(bad); err == nil {
			t.Errorf("accepted hostile report %s", bad)
		}
	}
	for _, c := range []TypeScriptComment{{"line", 0, 42}, {"line", 1, 41}, {"line", 0, 40}, {"line", 0, 41}} {
		cloned := valid
		cloned.Comments = []TypeScriptComment{c}
		if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
			t.Errorf("accepted bad range %#v", c)
		}
	}
	cloned := valid
	cloned.InputSHA256 = tsDigest([]byte("other"))
	if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
		t.Fatal("accepted forged input digest")
	}
	cloned = valid
	cloned.ProviderSHA256 = tsDigest([]byte("other"))
	if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
		t.Fatal("accepted forged provider digest")
	}
	for _, path := range []string{"/tmp/a.ts", "a/../b.ts", "a\\b.ts", strings.Repeat("a", 1022) + ".ts", strings.Repeat("a", 4094) + ".ts"} {
		cloned = valid
		cloned.Path = path
		if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
			t.Errorf("accepted hostile path %q", path)
		}
	}
	cloned = valid
	cloned.Language = "tsx"
	if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
		t.Fatal("accepted language/extension mismatch")
	}
	cloned = valid
	cloned.Path = strings.Repeat("😀", 1024) + ".ts"
	if _, err := ValidateTypeScriptReport(cloned, valid.ProviderSHA256, content); err == nil {
		t.Fatal("accepted non-BMP path boundary attack")
	}
}

func TestTypeScriptReportSchemaIsClosed(t *testing.T) {
	b, err := os.ReadFile("../../schema/typescript-comments.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatal("schema is open")
	}
	props := schema["properties"].(map[string]any)
	if len(schema["required"].([]any)) != 6 || props["comments"] == nil || props["path"].(map[string]any)["maxLength"] != float64(1024) || props["path"].(map[string]any)["pattern"] == nil || schema["allOf"] == nil {
		t.Fatal("schema report closure incomplete")
	}
}

func TestTypeScriptReportSchemaOracleMatrix(t *testing.T) {
	c := js.NewCompiler()
	schema, err := c.Compile("../../schema/typescript-comments.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]any{"apiVersion": typeScriptReportAPI, "language": "typescript", "path": "a.ts", "inputSHA256": tsDigest([]byte("x")), "providerSHA256": tsDigest([]byte("p")), "comments": []any{map[string]any{"kind": "line", "startByte": float64(0), "endByte": float64(2)}}}
	clone := func(in map[string]any) map[string]any {
		b, _ := json.Marshal(in)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return out
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"unknown", func(m map[string]any) { m["unknown"] = true }, false},
		{"missing", func(m map[string]any) { delete(m, "comments") }, false},
		{"null", func(m map[string]any) { m["comments"] = nil }, false},
		{"wrong scalar", func(m map[string]any) { m["language"] = 1 }, false},
		{"path absolute", func(m map[string]any) { m["path"] = "/tmp/a.ts" }, false},
		{"path traversal", func(m map[string]any) { m["path"] = "a/../b.ts" }, false},
		{"language extension", func(m map[string]any) { m["language"], m["path"] = "tsx", "a.ts" }, false},
		{"provider digest", func(m map[string]any) { m["providerSHA256"] = "sha256:bad" }, false},
		{"range negative", func(m map[string]any) { m["comments"].([]any)[0].(map[string]any)["startByte"] = -1 }, false},
		{"range fraction", func(m map[string]any) { m["comments"].([]any)[0].(map[string]any)["startByte"] = 1.5 }, false},
		{"range exponent", func(m map[string]any) { m["comments"].([]any)[0].(map[string]any)["startByte"] = 1e3 }, true},
	}
	for _, tc := range cases {
		instance := clone(valid)
		tc.mutate(instance)
		if got := schema.Validate(instance) == nil; got != tc.want {
			t.Errorf("schema case %s got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestTypeScriptReportSourceContractConstants(t *testing.T) {
	if MaxTypeScriptReportBytes != 8<<20 || MaxTypeScriptComments != 65536 {
		t.Fatal("report bounds changed")
	}
	if strings.Contains(typeScriptReportAPI, "approved") {
		t.Fatal("report contract gained authority")
	}
}

func TestTypeScriptReportBoundsAndUTF8Offsets(t *testing.T) {
	if _, err := ParseTypeScriptReport(bytes.Repeat([]byte("x"), MaxTypeScriptReportBytes+1)); err == nil {
		t.Fatal("oversized report accepted")
	}
	content := []byte("// é\n")
	r := TypeScriptReport{APIVersion: typeScriptReportAPI, Language: "typescript", Path: "a.ts", InputSHA256: tsDigest(content), ProviderSHA256: tsDigest([]byte("p")), Comments: []TypeScriptComment{{Kind: "line", StartByte: 0, EndByte: 4}}}
	if _, err := ValidateTypeScriptReport(r, r.ProviderSHA256, content); err == nil {
		t.Fatal("UTF-8 split comment span accepted")
	}
	var b strings.Builder
	b.WriteString(`{"apiVersion":"` + typeScriptReportAPI + `","language":"typescript","path":"a.ts","inputSHA256":"` + tsDigest(content) + `","providerSHA256":"` + r.ProviderSHA256 + `","comments":[`)
	for i := 0; i < MaxTypeScriptComments+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"kind":"line","startByte":0,"endByte":1}`)
	}
	b.WriteString(`]}`)
	if _, err := ParseTypeScriptReport([]byte(b.String())); err == nil {
		t.Fatal("oversized comment list accepted")
	}
}
