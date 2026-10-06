package resultdto

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

var updateSourceWireV3Schema = flag.Bool("update-source-wire-v3-schema", false, "Write the approved generated source v3 schema")

func sourceWireBody(t *testing.T) RootContextBody {
	t.Helper()
	b := rootWireBody(t)
	b.APIVersion = ContextRootV3
	p := &b.Packet
	source := p.Sources[0]
	source.ID = "context:source:dependency"
	source.Pin.Alias = "dependency"
	p.Sources = append(p.Sources, source)
	it := *p.Records[0].Descriptor
	it.ID = "context:resource:guide"
	it.SourceID = source.ID
	it.SourcePath = "context/dependency.md"
	it.Ownership.OwnerID = "context:owner:dependency"
	content := []byte("Read all required source guides; inert context only.\n")
	it.ContentSHA256 = evidencecas.Digest(content)
	p.Records = append(p.Records, contextindex.Record{ID: it.ID, Kind: it.Kind, ItemID: it.ID, SourceID: it.SourceID, Path: it.SourcePath, Name: it.ID, Line: 1, State: "declared", Descriptor: &it})
	p.RequiredFloor = append(p.RequiredFloor, source.ID, it.ID)
	p.SourceEvidence = append(p.SourceEvidence, contextindex.SourceEvidence{SourceID: source.ID, StatementCAS: source.Anchor.StatementCAS, Scope: "source-subject/publisher-evidence/item-bytes-mode"})
	p.Excerpts = append(p.Excerpts, contextpack.SourceExcerpt{NodeID: it.ID, Path: it.SourcePath, Start: 1, End: 1, Content: string(content), Digest: it.ContentSHA256})
	p.Relations = append(p.Relations, graphdoc.Edge{From: source.ID, To: it.ID, Kind: "source:anchors"})
	for range 32 {
		raw, _ := json.Marshal(p)
		if p.Bytes == len(raw) {
			break
		}
		p.Bytes = len(raw)
	}
	b.Files = append(b.Files, RootContextFile{SelectedIdentity: evidencecas.Digest([]byte("dependency guide")), ExportID: "dependency", SourcePath: it.SourcePath, TargetPath: it.SourcePath, Mode: it.Mode, ContentSHA256: it.ContentSHA256, Content: content})
	return b
}
func TestContextSourceWireV3SchemaAndLogicalRoundtrip(t *testing.T) {
	schema, e := ContextRootV3Schema()
	if e != nil {
		t.Fatal(e)
	}
	schema = append(schema, '\n')
	path := "../../schema/context-root-selection.v3.schema.json"
	if *updateSourceWireV3Schema {
		if e = os.WriteFile(path, schema, 0644); e != nil {
			t.Fatal(e)
		}
	}
	stored, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(schema, stored) {
		t.Fatal("v3 schema drift", e)
	}
	b := sourceWireBody(t)
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	document, e := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if e != nil {
		t.Fatal(e)
	}
	compiler := jsonschema.NewCompiler()
	if e = compiler.AddResource("https://tplaiter.dev/schema/context-root-selection.v3.schema.json", document); e != nil {
		t.Fatal(e)
	}
	compiled, e := compiler.Compile("https://tplaiter.dev/schema/context-root-selection.v3.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	value, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if e = compiled.Validate(value); e != nil {
		t.Fatal(e)
	}
	var decoded RootContextBody
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(b.Packet)
	z, _ := json.Marshal(decoded.Packet)
	if !bytes.Equal(a, z) || len(decoded.Files) != 2 || !bytes.Equal(decoded.Files[1].Content, b.Files[1].Content) || decoded.Packet.Bytes != len(a) {
		t.Fatal("lost whole logical data/images")
	}
	guard, e := RootGuardV3(b)
	if e != nil {
		t.Fatal(e)
	}
	g, e := DecodeRootGuardV3(guard)
	if e != nil {
		t.Fatal(e)
	}
	if len(g.Packet.Records) != 0 || len(g.Files) != 2 {
		t.Fatal("guard lost images or supplied replacement packet")
	}
	if _, e = DecodeRootGuardV2(guard); e == nil {
		t.Fatal("v3 guard confused v2")
	}
	t.Logf("v3 complete body=%d logicalBytes=%d images=2; versioned guard has no selection replacement", len(raw), b.Packet.Bytes)
}
func TestContextSourceWireV3StrictBodyImageAndBudget(t *testing.T) {
	b := sourceWireBody(t)
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(map[string]any){
		"case-extra-graph-key": func(x map[string]any) { g := x["graph"].(map[string]any); g["SELECTED"] = g["selected"] },
		"missing-zero-graph":   func(x map[string]any) { delete(x["graph"].(map[string]any), "edges") },
		"missing-pin":          func(x map[string]any) { delete(x, "bindingsDigest") },
		"unknown-authority":    func(x map[string]any) { x["authenticated"] = true },
		"image-hash":           func(x map[string]any) { x["files"].([]any)[0].(map[string]any)["content"] = "eA==" },
		"missing-image-key":    func(x map[string]any) { delete(x["files"].([]any)[0].(map[string]any), "mode") },
		"null-image":           func(x map[string]any) { x["files"] = nil },
		"floor": func(x map[string]any) {
			x["packet"].(map[string]any)["packet"].(map[string]any)["requiredFloor"] = []any{}
		},
		"source-default-ref": func(x map[string]any) {
			x["packet"].(map[string]any)["records"].([]any)[0].(map[string]any)["defaultsRef"] = -1
		},
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(raw, &x)
			mutate(x)
			bad, _ := json.Marshal(x)
			var out RootContextBody
			if json.Unmarshal(bad, &out) == nil {
				t.Fatal("malformed body accepted")
			}
		})
	}
	dup := bytes.Replace(raw, []byte(`"apiVersion":`), []byte(`"apiVersion":"duplicate","apiVersion":`), 1)
	var out RootContextBody
	if json.Unmarshal(dup, &out) == nil {
		t.Fatal("duplicate wire key")
	}
	b.Files[0].Content = []byte(strings.Repeat("x", 32769))
	b.Files[0].ContentSHA256 = evidencecas.Digest(b.Files[0].Content)
	if _, e = json.Marshal(b); e == nil {
		t.Fatal("body cap raised")
	}
	guard, e := RootGuardV3(sourceWireBody(t))
	if e != nil {
		t.Fatal(e)
	}
	var x map[string]any
	_ = json.Unmarshal(guard, &x)
	x["packet"] = map[string]any{"apiVersion": contextindex.APIVersion}
	bad, _ := json.Marshal(x)
	if _, e = DecodeRootGuardV3(bad); e == nil {
		t.Fatal("guard accepted caller packet")
	}
}

func TestContextSourceWireV3ImageTopologyAndGuardCounters(t *testing.T) {
	body := sourceWireBody(t)
	for name, mutate := range map[string]func(*RootContextBody){
		"duplicate":             func(b *RootContextBody) { b.Files[1] = b.Files[0] },
		"ancestor":              func(b *RootContextBody) { b.Files[0].TargetPath = "context" },
		"case-ancestor":         func(b *RootContextBody) { b.Files[0].TargetPath = "CONTEXT" },
		"unicode-fold-ancestor": func(b *RootContextBody) { b.Files[0].TargetPath = "SK"; b.Files[1].TargetPath = "ſk/guide.md" },
		"content-hash":          func(b *RootContextBody) { b.Files[0].Content = []byte("tampered") },
	} {
		t.Run(name, func(t *testing.T) {
			b := sourceWireBody(t)
			mutate(&b)
			if _, e := json.Marshal(b); e == nil {
				t.Fatal("invalid outbound image accepted")
			}
			if _, e := RootGuardV3(b); e == nil {
				t.Fatal("invalid guard image accepted")
			}
		})
	}
	// Shared exact target images preserve each different complete export identity.
	shared := body.Files[0]
	shared.SelectedIdentity = evidencecas.Digest([]byte("other export"))
	body.Files = append(body.Files, shared)
	raw, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	var decoded RootContextBody
	if e = json.Unmarshal(raw, &decoded); e != nil || len(decoded.Files) != 3 {
		t.Fatal("lost shared target/export identity", e)
	}
	guard, e := RootGuardV3(sourceWireBody(t))
	if e != nil {
		t.Fatal(e)
	}
	var x map[string]any
	_ = json.Unmarshal(guard, &x)
	delete(x, "bindingsDigest")
	bad, _ := json.Marshal(x)
	if _, e = DecodeRootGuardV3(bad); e == nil {
		t.Fatal("missing guard pin accepted")
	}
}
