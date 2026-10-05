package contextsource

import (
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/deps"
	"strings"
	"testing"
)

func contextTestBinding() ContextSourceBindings {
	return ContextSourceBindings{APIVersion: ContextSourceBindingsAPIVersion, Kind: "ContextSourceBindings", Source: ContextCatalogBinding{Alias: "root", ProviderID: "public.provider", Parameters: []deps.Parameter{{Name: "flavor", Value: json.RawMessage(`"plain"`)}}, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}, Dependencies: []ContextDependencyBinding{{Alias: "dep", ProviderID: "public.dependency", Parameters: []deps.Parameter{}}}}
}
func TestContextBindingsV2ClosedWireAndSchema(t *testing.T) {
	good := contextTestBinding()
	raw := contextJSON(t, good)
	schema := contextSchema(t, "context-source-bindings.v2")
	if _, err := DecodeContextSourceBindingsV2(raw); err != nil {
		t.Fatal(err)
	}
	contextSchemaCheck(t, schema, raw, true)
	for _, bad := range []string{strings.Replace(string(raw), `"kind":"ContextSourceBindings",`, "", 1), strings.Replace(string(raw), `"dependencies":[`, `"ownCommit":"`+strings.Repeat("a", 40)+`","dependencies":[`, 1), strings.Replace(string(raw), `"providerID":"public.provider"`, `"providerID":"invalid provider"`, 1), strings.Replace(string(raw), `"parameters":[{"name":"flavor","value":"plain"}]`, `"parameters":null`, 1), strings.Replace(string(raw), `"value":"plain"`, `"value":{}`, 1)} {
		if _, err := DecodeContextSourceBindingsV2([]byte(bad)); err == nil {
			t.Fatal("invalid bindings accepted")
		}
		contextSchemaCheck(t, schema, []byte(bad), false)
	}
	for _, path := range []string{"../outside", "/absolute", "catalog/CON.json", "catalog/a\\b", "catalog/a/../b", "catalog/a\n"} {
		b := contextTestBinding()
		b.Source.EntriesPath = path
		if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err == nil {
			t.Fatalf("path %q accepted", path)
		}
	}
	for _, value := range []string{`null`, `[]`, `1.0`, `1e1`, `-0`, `9007199254740992`} {
		b := contextTestBinding()
		b.Source.Parameters[0].Value = json.RawMessage(value)
		if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err == nil {
			t.Fatalf("typed value %s accepted", value)
		}
	}
	for _, value := range []string{`"plain"`, `true`, `0`, `-1`, `9007199254740991`} {
		b := contextTestBinding()
		b.Source.Parameters[0].Value = json.RawMessage(value)
		if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err != nil {
			t.Fatalf("typed value %s: %v", value, err)
		}
		contextSchemaCheck(t, schema, contextJSON(t, b), true)
	}
	b := contextTestBinding()
	b.Dependencies[0].Alias = b.Source.Alias
	if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err == nil {
		t.Fatal("self alias accepted")
	}
	b = contextTestBinding()
	b.Dependencies = append(b.Dependencies, b.Dependencies[0])
	if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	b = contextTestBinding()
	b.Source.Parameters = append(b.Source.Parameters, b.Source.Parameters[0])
	if _, err := DecodeContextSourceBindingsV2(contextJSON(t, b)); err == nil {
		t.Fatal("duplicate parameter accepted")
	}
	if _, err := DecodeContextSourceBindingsV2(make([]byte, (64<<10)+1)); err == nil {
		t.Fatal("bindings byte bound ignored")
	}
}
