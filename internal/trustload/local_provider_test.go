package trustload

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func localRegistrationBytes(t *testing.T) []byte {
	t.Helper()
	v := localRegistration{APIVersion: LocalProviderRegistrationVersion, Kind: "LocalProviderRegistration", RegistrationID: "public-synthetic", InstallationID: "install.synthetic", ProjectKeys: []string{"default"}, Protocol: "local-provider.session/v1", Qualification: LocalObserved, Limits: LocalReadLimits{FrameBytes: 32768, TotalBytes: 2097152, Pages: 128, SourceBytes: 8192, DeadlineMs: 2000}}
	v.Endpoint.Kind = "unix"
	v.Endpoint.SocketPath = "/tmp/synthetic/session.sock"
	v.Endpoint.OwnerUID = 501
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLocalRegistrationClosedObservedOnly(t *testing.T) {
	raw := localRegistrationBytes(t)
	if _, err := decodeLocalRegistration(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["qualification"] = "trusted" },
		func(m map[string]any) { m["organizationCertified"] = true },
		func(m map[string]any) { m["command"] = "producer" },
		func(m map[string]any) { m["projectKeys"] = []string{"default", "default"} },
		func(m map[string]any) { m["endpoint"].(map[string]any)["ownerUID"] = nil },
		func(m map[string]any) { delete(m["endpoint"].(map[string]any), "ownerUID") },
		func(m map[string]any) { m["endpoint"].(map[string]any)["socketPath"] = "relative.sock" },
		func(m map[string]any) { m["limits"].(map[string]any)["sourceBytes"] = 8193 },
		func(m map[string]any) { m["limits"].(map[string]any)["deadlineMs"] = 2001 },
	} {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		change(m)
		bad, _ := json.Marshal(m)
		if _, err := decodeLocalRegistration(bad); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
	var r *Runtime
	if _, err := r.OpenLocalProvider(context.Background(), "public-synthetic"); err == nil {
		t.Fatal("nil runtime establishes connection")
	}
	var p LocalProvider
	if _, err := p.Read(make([]byte, 1)); err == nil {
		t.Fatal("zero connection")
	}
	if err := p.Recheck(context.Background()); err == nil {
		t.Fatal("zero selection")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRegistrationTokenSchemaLexicalParity(t *testing.T) {
	schema, err := jsonschema.NewCompiler().Compile("../../schema/local-provider-registration.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	previewRegistration, err := jsonschema.NewCompiler().Compile("../../schema/context-local-preview.v1.schema.json#/properties/selection/properties/registrationID")
	if err != nil {
		t.Fatal(err)
	}
	previewProject, err := jsonschema.NewCompiler().Compile("../../schema/context-local-preview.v1.schema.json#/properties/selection/properties/projectContext")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, value             string
		admitted, schemaAllowed bool
	}{
		{"plain", "host", true, true},
		{"nul", "host\x00preview", false, false},
		{"tab", "host\tpreview", false, false},
		{"cr", "host\rpreview", false, false},
		{"lf", "host\npreview", false, false},
		{"trailing-lf", "host\n", false, false},
		{"space", "host preview", false, false},
		{"slash", "host/preview", false, false},
		{"backslash", "host\\preview", false, false},
		{"ff", "host\fpreview", true, true},
		{"vt", "host\vpreview", true, true},
		{"nbsp", "host\u00a0preview", true, true},
		{"em-space", "host\u2003preview", true, true},
		{"valid-utf8", "hôte-文", true, true},
		{"ascii-64", strings.Repeat("a", 64), true, true},
		{"ascii-65", strings.Repeat("a", 65), false, false},
		{"utf8-64-bytes", strings.Repeat("é", 32), true, true},
		{"utf8-66-bytes-33-runes", strings.Repeat("é", 33), false, true},
	}
	for _, tc := range cases {
		for _, field := range []string{"registrationID", "projectKeys"} {
			t.Run(tc.name+"/"+field, func(t *testing.T) {
				var value map[string]any
				_ = json.Unmarshal(localRegistrationBytes(t), &value)
				if field == "registrationID" {
					value[field] = tc.value
				} else {
					value[field] = []string{tc.value}
				}
				raw, e := json.Marshal(value)
				if e != nil {
					t.Fatal(e)
				}
				if got := ValidateLocalProviderDocument(raw) == nil; got != tc.admitted {
					t.Fatalf("admission=%v want %v", got, tc.admitted)
				}
				schemaValue, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if e != nil {
					t.Fatal(e)
				}
				if got := schema.Validate(schemaValue) == nil; got != tc.schemaAllowed {
					t.Fatalf("schema=%v want %v", got, tc.schemaAllowed)
				}
				previewScalar := previewRegistration
				if field == "projectKeys" {
					previewScalar = previewProject
				}
				if got := previewScalar.Validate(tc.value) == nil; got != tc.schemaAllowed {
					t.Fatalf("preview scalar schema=%v want %v", got, tc.schemaAllowed)
				}
			})
		}
	}
	invalid := string([]byte{'h', 0xff})
	if utf8.ValidString(invalid) || token(invalid) {
		t.Fatal("invalid UTF-8 token")
	}
	invalidRaw := bytes.Replace(localRegistrationBytes(t), []byte("public-synthetic"), []byte{'h', 0xff}, 1)
	if ValidateLocalProviderDocument(invalidRaw) == nil {
		t.Fatal("invalid UTF-8 JSON")
	}
}
