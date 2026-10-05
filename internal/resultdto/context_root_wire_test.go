package resultdto

import (
	"bytes"
	"encoding/json"
	"flag"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"os"
	"strings"
	"testing"
)

var updateContextRootWireSchema = flag.Bool("update-context-root-wire-schema", false, "Write the approved generated ROOT v2 schema")

func TestContextRootV2SchemaFile(t *testing.T) {
	raw, e := ContextRootV2Schema()
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := "../../schema/context-root-selection.v2.schema.json"
	if *updateContextRootWireSchema {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, b) {
		t.Fatal("ROOT v2 schema drift", e)
	}
	if len(raw) == 0 {
		t.Fatal("schema absent")
	}
}

// This is inert descriptor data. The installed process proof supplies authority.
func rootWireBody(t *testing.T) RootContextBody {
	t.Helper()
	raw, e := os.ReadFile("../../testdata/knowledge/catalog.json")
	if e != nil {
		t.Fatal(e)
	}
	d, e := knowledge.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	source := d.Sources[0]
	source.ID = "root:source:installed"
	it := d.Items[2]
	it.ID = "root:resource:r-" + strings.Repeat("a", 32)
	it.Kind = "resource"
	it.SourceID = source.ID
	it.SourcePath = "context/guide.md"
	it.Mode = "100644"
	it.Requires = []string{}
	it.Produces = []string{}
	it.Export = nil
	content := []byte("Select complete task context.\n")
	it.ContentSHA256 = evidencecas.Digest(content)
	packet := contextindex.Packet{APIVersion: contextindex.APIVersion, GraphDigest: evidencecas.Digest([]byte("graph")), Records: []contextindex.Record{{ID: it.ID, Kind: it.Kind, ItemID: it.ID, SourceID: it.SourceID, Path: it.SourcePath, Name: it.ID, Line: 1, State: "declared", Descriptor: &it}}, Sources: []knowledge.Source{source}, Relations: []graphdoc.Edge{}, ExternalReferences: []contextindex.Reference{}, RequiredFloor: []string{it.ID, source.ID}, SourceEvidence: []contextindex.SourceEvidence{{SourceID: source.ID, StatementCAS: source.Anchor.StatementCAS, Scope: "source-subject/publisher-evidence/item-bytes-mode"}}, Excerpts: []contextpack.SourceExcerpt{{NodeID: it.ID, Path: it.SourcePath, Start: 1, End: 1, Content: string(content), Digest: it.ContentSHA256}}, TotalMatches: 1}
	for range 32 {
		b, _ := json.Marshal(packet)
		if packet.Bytes == len(b) {
			break
		}
		packet.Bytes = len(b)
	}
	return RootContextBody{APIVersion: ContextRootV2, Packet: packet, Graph: exports.ExportGraph{Selected: []exports.SelectedExport{}, Edges: []exports.ExportEdge{}}, Selections: []exports.Selection{}, Files: []RootContextFile{{SelectedIdentity: evidencecas.Digest([]byte("selected")), ExportID: "guide", SourcePath: it.SourcePath, TargetPath: "context/guide.md", Mode: it.Mode, ContentSHA256: it.ContentSHA256, Content: content}}}
}
func TestContextRootWireV2RoundtripAndLegacySerialization(t *testing.T) {
	b := rootWireBody(t)
	wire, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	var restored RootContextBody
	if e = json.Unmarshal(wire, &restored); e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(b.Packet)
	z, _ := json.Marshal(restored.Packet)
	if !bytes.Equal(a, z) || !bytes.Equal(b.Files[0].Content, restored.Files[0].Content) {
		t.Fatal("logical packet or procedure changed")
	}
	b.APIVersion = "tplaiter.dev/context-root-selection/v1"
	type legacy RootContextBody
	want, _ := json.Marshal(legacy(b))
	got, _ := json.Marshal(b)
	if !bytes.Equal(got, want) {
		t.Fatal("legacy body wire changed")
	}
	r := ContextRootSelectionData{Body: restored}
	for range 32 {
		v, _ := json.Marshal(r)
		if r.Bytes == len(v) {
			break
		}
		r.Bytes = len(v)
	}
	actual, _ := json.Marshal(r)
	if r.Bytes != len(actual) {
		t.Fatal("ROOT wire byte count")
	}
	t.Logf("compiled decoder restores every logical field and guide; v1 byte identity; ROOT DTO measured=%d", r.Bytes)
}
func TestContextRootWireV2StrictCounter(t *testing.T) {
	b := rootWireBody(t)
	wire, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing-body-pin": func(x map[string]any) { delete(x, "rootLockDigest") },
		"unknown-body":     func(x map[string]any) { x["authenticated"] = true },
		"changed-file":     func(x map[string]any) { x["files"].([]any)[0].(map[string]any)["content"] = "eA==" },
		"missing-image":    func(x map[string]any) { x["files"] = []any{} },
		"missing-file-key": func(x map[string]any) { delete(x["files"].([]any)[0].(map[string]any), "mode") },
		"changed-floor": func(x map[string]any) {
			x["packet"].(map[string]any)["packet"].(map[string]any)["requiredFloor"] = []any{}
		},
		"null-image": func(x map[string]any) { x["files"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var x map[string]any
			_ = json.Unmarshal(wire, &x)
			mutate(x)
			raw, _ := json.Marshal(x)
			var out RootContextBody
			if json.Unmarshal(raw, &out) == nil {
				t.Fatal("invalid complete body decoded")
			}
		})
	}
	dup := bytes.Replace(wire, []byte(`"apiVersion":`), []byte(`"apiVersion":"duplicate","apiVersion":`), 1)
	var out RootContextBody
	if json.Unmarshal(dup, &out) == nil {
		t.Fatal("duplicate body key accepted")
	}
}
