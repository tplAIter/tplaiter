package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/semanticpreview"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

var semanticProcess = flag.Bool("semantic-installed-process", false, "finite normal configured synthetic-operator semantic observation proof")

func semanticData(t *testing.T, raw []byte) resultdto.SemanticPreviewData {
	t.Helper()
	env, e := resultdto.Decode(raw)
	if e != nil || env.Status != resultdto.StatusOK || env.Operation != resultdto.OperationSemanticPreview {
		t.Fatalf("semantic envelope: %v %s", e, raw)
	}
	d, e := resultdto.DecodeSemanticPreviewData(env.Data)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestSemanticInstalledConfiguredOperatorCLIAndMCP(t *testing.T) {
	if !*semanticProcess {
		t.Skip("explicit finite installed proof")
	}
	// Reuse actual public Capture/Generate/provision/New; no lock or runtime is
	// handwritten. This source is synthetic operator-authorized test data.
	f, _ := graphInstalledFixture(t)
	source := []byte("package sample\nimport \"strings\"\nfunc Handle() string {\n // insertion point\n return strings.TrimSpace(\"before\")\n}\n")
	p := filepath.Join(f.project, "sample.go")
	if e := os.WriteFile(p, source, 0644); e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(f.base, "semantic-request.json")
	request := semanticpreview.Request{APIVersion: semanticpreview.RequestVersion, Action: "anchors", Paths: []string{"sample.go"}}
	write := func(q semanticpreview.Request) {
		t.Helper()
		if e := os.WriteFile(input, rootB2JSON(t, q), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(request)
	before := rootB2Image(t, f.project, f.home, f.install)
	raw, e := f.run("semantic", "preview", "--input", input, "--dir", f.project, "--max-bytes", "32768", "--json")
	graphReceipt(t, "semantic-cli-anchors.json", raw)
	if e != nil {
		t.Fatalf("anchors: %v %s", e, raw)
	}
	anchors := semanticData(t, raw)
	if !reflect.DeepEqual(anchors.Images[0].Before, source) {
		t.Fatal("authentic byte image lost")
	}
	pick := func(kind string) resultdto.SemanticAnchor {
		for _, a := range anchors.Images[0].BeforeAnchors {
			if a.Kind == kind {
				return a
			}
		}
		t.Fatal("missing actual anchor", kind)
		return resultdto.SemanticAnchor{}
	}
	cases := []semanticpreview.Edit{
		{ID: "body", Path: "sample.go", Intent: "go.function-body.replace", Anchor: pick("function-body"), Payload: `{ return "after" }`},
		{ID: "add", Path: "sample.go", Intent: "go.import.add", Anchor: pick("import-boundary"), ImportPath: "fmt"},
		{ID: "remove", Path: "sample.go", Intent: "go.import.remove", Anchor: pick("import"), ImportPath: "strings"},
		{ID: "comment", Path: "sample.go", Intent: "go.comment-anchor.insert-statements", Anchor: pick("comment"), Comment: "// insertion point", Payload: `_ = "inserted"`},
	}
	server := rootB2StartMCP(t, f)
	for _, edit := range cases {
		edit.ExpectedFileDigest = evidencecas.Digest(source)
		edit.BeforeGraphDigest = anchors.BeforeGraph.Digest
		q := semanticpreview.Request{APIVersion: semanticpreview.RequestVersion, Action: "preview", Edits: []semanticpreview.Edit{edit}}
		write(q)
		cli, e := f.run("semantic", "preview", "--input", input, "--dir", f.project, "--max-bytes", "32768", "--json")
		graphReceipt(t, "semantic-cli-"+edit.ID+".json", cli)
		if e != nil {
			t.Fatalf("CLI %s: %v %s", edit.ID, e, cli)
		}
		data := semanticData(t, cli)
		if len(cli) > 32768 || len(data.Edits) != 1 || len(data.Images) != 1 || len(data.Images[0].Diff) == 0 || !reflect.DeepEqual(data.Images[0].Before, source) || data.CompilerVerification != "not-performed" {
			t.Fatal("incomplete truthful preview", edit.ID)
		}
		server.write(t, map[string]any{"jsonrpc": "2.0", "id": edit.ID + "<&\\\"", "method": "tools/call", "params": map[string]any{"name": "semantic_preview", "arguments": map[string]any{"dir": f.project, "input": input, "maxBytes": 32768}}})
		frame := server.read(t)
		graphReceipt(t, "semantic-mcp-"+edit.ID+".json", frame)
		var response struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError           bool            `json:"isError"`
				StructuredContent json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if e = json.Unmarshal(frame, &response); e != nil || len(response.Error) > 0 || response.Result.IsError || len(frame) > 32768 {
			t.Fatalf("MCP %s: %v %s", edit.ID, e, frame)
		}
		observed := semanticData(t, response.Result.StructuredContent)
		if !reflect.DeepEqual(data, observed) {
			t.Fatal("CLI/MCP factual observation mismatch", edit.ID)
		}
		t.Logf("actual %s CLI=%d MCP=%d completeImages=%d original=%s after=%s", edit.ID, len(cli), len(frame), len(data.Images), data.Images[0].BeforeDigest, data.Images[0].AfterDigest)
	}
	// Transport controls operate on real registered route, not a substituted
	// handler. The metadata alone cannot fit; then the next valid request works.
	server.write(t, map[string]any{"jsonrpc": "2.0", "id": strings.Repeat("<", 10000), "method": "tools/call", "params": map[string]any{"name": "semantic_preview", "arguments": map[string]any{"dir": f.project, "input": input, "maxBytes": 1024}}})
	refused := server.read(t)
	graphReceipt(t, "semantic-mcp-metadata-refusal.json", refused)
	if len(refused) > 1024 || !strings.Contains(string(refused), `"id":null`) {
		t.Fatal("unbounded metadata refusal")
	}
	server.close(t)
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("readonly preview mutated project/install/home")
	}
	// Real direct-consumer capture keeps its session, returns defensive images,
	// refuses stale content/cancel/closed access and never writes a replacement.
	r, e := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	q := semanticpreview.Request{APIVersion: semanticpreview.RequestVersion, Action: "anchors", Paths: []string{"sample.go"}}
	preview, e := semanticpreview.Prepare(context.Background(), r, q, runtimeassembly.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer preview.Close()
	data, e := preview.Result(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	data.Images[0].Before[0] = 'X'
	fresh, e := preview.Result(context.Background())
	if e != nil || fresh.Images[0].Before[0] != 'p' {
		t.Fatal("mutable projection aliases owned capture", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = preview.Recheck(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled observation remained fresh", e)
	}
	if e = os.WriteFile(p, []byte("package sample\nfunc Handle(){}\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = preview.Result(context.Background()); e == nil {
		t.Fatal("stale source delivered")
	}
	preview.Close()
	if preview.Recheck(context.Background()) == nil {
		t.Fatal("closed capture remained valid")
	}
	// Restore only fixture-owned bytes for the final exact nonmutation receipt.
	if e = os.WriteFile(p, source, 0644); e != nil {
		t.Fatal(e)
	}
	var zero graphcmd.SemanticFiles
	if zero.Recheck(context.Background()) == nil {
		t.Fatal("zero capture supplied authority")
	}
}
