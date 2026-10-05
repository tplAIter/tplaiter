package contextcmd

import (
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/deps"
	"os"
	"strings"
	"testing"
)

func rootBindingWire() []byte {
	raw, _ := json.Marshal(rootBindings{APIVersion: RootBindingsAPIVersion, Kind: "ContextRootBindings", Source: rootBinding{Alias: "base", ProviderID: "neutral", Parameters: []deps.Parameter{}, EntriesPath: "catalog/entries.json", PayloadDirectory: "catalog/payloads", ToolPath: "catalog/tool.md"}})
	return raw
}

func TestRootBindingsStrict(t *testing.T) {
	raw := rootBindingWire()
	if _, err := decodeRootBindings(raw); err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{
		"missing":    []byte(strings.Replace(string(raw), `"parameters":[],`, "", 1)),
		"null":       []byte(strings.Replace(string(raw), `"parameters":[]`, `"parameters":null`, 1)),
		"parameters": []byte(strings.Replace(string(raw), `"parameters":[]`, `"parameters":[{"name":"x","value":true}]`, 1)),
		"unknown":    []byte(strings.Replace(string(raw), `"kind":`, `"subject":{},"kind":`, 1)),
		"duplicate":  []byte(strings.Replace(string(raw), `"alias":"base"`, `"alias":"base","alias":"base"`, 1)),
		"case-key":   []byte(strings.Replace(string(raw), `"alias":`, `"Alias":`, 1)),
		"traversal":  []byte(strings.Replace(string(raw), `catalog/entries.json`, `../entries.json`, 1)),
		"absolute":   []byte(strings.Replace(string(raw), `catalog/entries.json`, `/entries.json`, 1)),
		"version":    []byte(strings.Replace(string(raw), RootBindingsAPIVersion, RootBindingsAPIVersion+"x", 1)),
		"own-commit": []byte(strings.Replace(string(raw), `"alias":`, `"commit":"abc","alias":`, 1)),
		"oversize":   []byte(strings.Repeat(" ", 64<<10+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRootBindings(wire); err == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
	// Keep the shipped schema's closed field inventory consistent with the actual
	// decoder, without pretending schema validation authenticates a source.
	schema, err := os.ReadFile("../../schema/context-root-bindings.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err = json.Unmarshal(schema, &d); err != nil {
		t.Fatal(err)
	}
	if d["additionalProperties"] != false {
		t.Fatal("schema is open")
	}
}
