package exports

import (
	"context"
	"encoding/json"
	js "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
)

func TestSourceLocalIndexClosedGrammarAndMappingMetadata(t *testing.T) {
	entry := ExportEntry{ID: "react.router", Domain: "block", Name: "router", Version: "1.0.0-preview.1", ContentDigest: digestBytes([]byte("payload")), Requires: []ExportRequirement{}, Parameters: []ScalarParameter{}, ToolDigest: digestBytes([]byte("lock"))}
	raw, _ := json.Marshal(SourceLocalExportIndex{SourceLocalExportIndexAPIVersion, []ExportEntry{entry}})
	if _, err := ParseSourceLocalExportIndex(raw); err != nil {
		t.Fatal(err)
	}
	bads := [][]byte{
		[]byte(strings.Replace(string(raw), `"exports":`, `"provider":"caller","exports":`, 1)),
		[]byte(strings.Replace(string(raw), `"version":"1.0.0-preview.1"`, `"version":"1.0"`, 1)),
		[]byte(strings.Replace(string(raw), `"name":"router"`, `"name":"../router"`, 1)),
		[]byte(strings.Replace(string(raw), `"parameters":[]`, `"parameters":null`, 1)),
		[]byte(strings.Replace(string(raw), `"requires":[]`, `"requires":[],"requires":[]`, 1)),
		[]byte(`{"apiVersion":"tplaiter.dev/source-local-export-index/v1","exports":[]}`),
		[]byte(strings.Repeat(" ", 64<<10+1)),
	}
	for i, b := range bads {
		if _, err := ParseSourceLocalExportIndex(b); err == nil {
			t.Fatalf("bad index %d accepted", i)
		}
	}
	repeated, _ := json.Marshal(SourceLocalExportIndex{SourceLocalExportIndexAPIVersion, []ExportEntry{entry, entry}})
	if _, err := ParseSourceLocalExportIndex(repeated); err == nil {
		t.Fatal("duplicate index accepted")
	}
}

func TestRootRulesRejectMissingOpaqueSourceAndUnsafeMappings(t *testing.T) {
	for _, source := range []*deps.VerifiedSource{nil, {}} {
		if _, err := PrepareRootRules(context.Background(), source, SourcePin{}); err == nil {
			t.Fatal("unproduced source accepted")
		}
	}
	for _, target := range []string{"../escape", "/absolute", "a//b", "a\\b", "a\x00b", "{{"} {
		if rootTarget(target) == nil {
			t.Fatalf("unsafe target %q", target)
		}
	}
	if err := rootTarget("src/pages/{{ .Name.Pascal }}Route.tsx"); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"scripts":{"build":"tsc -b && vite build"},"dependencies":{"@scope/name":"1.2.3"}}`)
	if !rootSlotMatches(raw, "/scripts/build", "tsc -b && vite build") || !rootSlotMatches(raw, "/dependencies/@scope~1name", "1.2.3") || rootSlotMatches(raw, "/scripts/missing", "") || rootSlotMatches(raw, "/scripts/build", "invented") {
		t.Fatal("original slot ownership mismatch")
	}
}

func TestRootRuleCompleteOriginalDataIdentity(t *testing.T) {
	closure := json.RawMessage(`{"pin":{"evidenceDigest":"actual-statement-cas"},"entries":[{"path":"all-original-leaves"}]}`)
	record := json.RawMessage(`{"target":"package.json","entry":{"path":"react-files/package.json.tmpl","mode":"100644","body":"original"}}`)
	id, digest, err := rootRuleIdentity(closure, "file", record)
	if err != nil {
		t.Fatal(err)
	}
	again, same, err := rootRuleIdentity(closure, "file", record)
	if err != nil || again != id || same != digest {
		t.Fatal("unstable identity")
	}
	_, changed, err := rootRuleIdentity(json.RawMessage(`{"pin":{"evidenceDigest":"different-statement-cas"},"entries":[{"path":"all-original-leaves"}]}`), "file", record)
	if err != nil || changed == digest {
		t.Fatal("full source/evidence closure omitted")
	}
	newid, newdigest, err := rootRuleIdentity(closure, "file", json.RawMessage(strings.Replace(string(record), "100644", "100755", 1)))
	if err != nil || newid == id || newdigest == digest {
		t.Fatal("original mode omitted")
	}
	if digest == digestBytes(record) || digest == digestBytes(closure) {
		t.Fatal("raw hash substituted for root-rule domain")
	}
	if _, _, err := rootRuleIdentity(closure, "file", json.RawMessage(`{"target":"a","target":"b"}`)); err == nil {
		t.Fatal("duplicate original fields accepted")
	}
}

func TestSourceLocalIndexSchemaParity(t *testing.T) {
	raw, err := os.ReadFile("../../schema/source-local-export-index.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	const uri = "https://tplaiter.dev/schema/source-local-export-index.v1.schema.json"
	if err = c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	entry := ExportEntry{ID: "react.router", Domain: "block", Name: "router", Version: "1.0.0-preview.1", ContentDigest: digestBytes([]byte("payload")), Requires: []ExportRequirement{}, Parameters: []ScalarParameter{}, ToolDigest: digestBytes([]byte("lock"))}
	valid, _ := json.Marshal(SourceLocalExportIndex{SourceLocalExportIndexAPIVersion, []ExportEntry{entry}})
	for _, wire := range [][]byte{valid, []byte(strings.Replace(string(valid), `"name":"router"`, `"name":"../router"`, 1)), []byte(strings.Replace(string(valid), `"version":"1.0.0-preview.1"`, `"version":"1.0.0-01"`, 1)), []byte(strings.Replace(string(valid), `"exports":`, `"provider":"caller","exports":`, 1))} {
		v, err := js.UnmarshalJSON(strings.NewReader(string(wire)))
		if err != nil {
			t.Fatal(err)
		}
		schemaErr := schema.Validate(v)
		_, parseErr := ParseSourceLocalExportIndex(wire)
		if (schemaErr == nil) != (parseErr == nil) {
			t.Fatalf("schema/parser mismatch: %s: %v/%v", wire, schemaErr, parseErr)
		}
	}
}
