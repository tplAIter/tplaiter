package mcpsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
)

// Capture observes actual compiled contracts into a separate evidence directory;
// it never changes the checked-in oracle or invokes the application.
func TestTemplateDiscoveryCompiledContracts(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	tools := s.MCP().ListTools()
	if len(tools) != 38 {
		t.Fatal("original37 + discovery inventory", len(tools))
	}
	tool, ok := tools["template_discover"]
	if !ok || tool.Tool.Annotations.ReadOnlyHint == nil || !*tool.Tool.Annotations.ReadOnlyHint {
		t.Fatal("read route missing")
	}
	compileToolSchema(t, tool.Tool.RawOutputSchema)
	actualData, e := dataSchemas[resultdto.OperationTemplateDiscover]()
	if e != nil {
		t.Fatal(e)
	}
	schemaFile, e := os.ReadFile(filepath.Join("..", "..", "schema", "template-discovery.v1.schema.json"))
	if e != nil {
		t.Fatal(e)
	}
	var fromFile, fromCode any
	if json.Unmarshal(schemaFile, &fromFile) != nil || json.Unmarshal(actualData, &fromCode) != nil || !reflect.DeepEqual(fromFile, fromCode) {
		t.Fatal("standalone discovery schema differs from actual compiled output contract")
	}

	raw, _ := json.Marshal(tool.Tool)
	var descriptor map[string]any
	_ = json.Unmarshal(raw, &descriptor)
	props := descriptor["inputSchema"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"task", "sourceInput", "projectContext", "dir", "language", "framework", "labels", "maxCandidates", "limit", "maxBytes"} {
		if props[key] == nil {
			t.Fatal("missing actual field", key)
		}
	}
	if dir := os.Getenv("TPLAITER_DISCOVERY_CONTRACT_CAPTURE"); dir != "" {
		names := []string{}
		for name := range tools {
			names = append(names, name)
		}
		sort.Strings(names)
		list := []json.RawMessage{}
		for _, name := range names {
			v, e := json.Marshal(tools[name].Tool)
			if e != nil {
				t.Fatal(e)
			}
			list = append(list, v)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+"/tools.schema.actual.json", buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		raw, err := dataSchemas[resultdto.OperationTemplateDiscover]()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dir+"/discovery.schema.actual.json", raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestTemplateDiscoveryMCPActualArgumentRoute(t *testing.T) {
	a := templateDiscoverArgs{Task: "Создать сервис go", SourceInput: "/read/selection.json", ProjectContext: "root", Dir: "/read/project", Language: "go", Framework: "temporal", Labels: []string{"purpose=service", "lang=go"}, MaxCandidates: 7, Limit: 2, MaxBytes: 4096}
	expected := []string{"template", "discover", "--task", a.Task, "--source-input", a.SourceInput, "--project-context", "root", "--dir", a.Dir, "--language", "go", "--framework", "temporal", "--label", "purpose=service", "--label", "lang=go", "--max-candidates", "7", "--limit", "2", "--max-bytes", "4096"}
	if !reflect.DeepEqual(argvTemplateDiscover(a), expected) {
		t.Fatal("CLI/MCP argv diverges")
	}
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, withJSONFlag(expected), execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationTemplateDiscover, func(r *resultdto.Result) {
		data, err := d.Rank(d.Query{Task: "entity"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.SetData(data); err != nil {
			t.Fatal(err)
		}
	})}})
	c := newTestClient(t, runner)
	raw, _ := json.Marshal(a)
	var args map[string]any
	_ = json.Unmarshal(raw, &args)
	got := callTool(t, c, "template_discover", args)
	if !got.IsError || structuredEnvelope(t, got).Operation != resultdto.OperationTemplateDiscover || len(runner.Calls) != 0 {
		t.Fatal("unbound transport must not invoke child", resultText(t, got))
	}
	validateStructured(t, compileToolSchema(t, New(fakeExe, "test", nil).MCP().ListTools()["template_discover"].Tool.RawOutputSchema), got, "discovery")
	pin := argvTemplateShowPinned("examples/go-service", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(pin) != 7 || pin[3] != "--commit" || pin[5] != "--manifest-sha256" {
		t.Fatal("pinned show transport", pin)
	}
	follow := map[string]any{"dir": "/read/project", "projectContext": "root", "sourceInput": "/read/selection.json", "selectors": []string{"base.skill.review"}, "limit": 1, "maxBytes": 4096, "representation": "page"}
	encoded, _ := json.Marshal(follow)
	var ga graphArgs
	if err := json.Unmarshal(encoded, &ga); err != nil {
		t.Fatal(err)
	}
	argv := graphArgv("exports", ga)
	if !reflect.DeepEqual(argv, []string{"graph", "exports", "--project-context", "root", "--dir", "/read/project", "--source-input", "/read/selection.json", "--representation", "page", "--select", "base.skill.review", "--limit", "1", "--max-bytes", "4096"}) {
		t.Fatal("actual graph_exports transport parity", argv)
	}
}

func TestTemplateDiscoveryExactIDPresentationAndOwnership(t *testing.T) {
	var projected [2][]byte
	for i, id := range []string{"9007199254740992", "9007199254740993"} {
		layout := resultwire.DiscoveryFrameLayout{APIVersion: resultwire.DiscoveryFrameVersion, ID: json.RawMessage(id), Ceiling: 2048}
		encoded, e := resultwire.EncodeDiscoveryFrame(layout)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := resultwire.DecodeDiscoveryFrame(encoded)
		if e != nil || !bytes.Equal(decoded.ID, layout.ID) {
			t.Fatal("exact codec", e)
		}
		raw, e := json.Marshal(decoded.RequestID())
		if e != nil || string(raw) != id {
			t.Fatal("numeric ID rounded", string(raw), e)
		}
		var sdk mcp.RequestId
		if e = json.Unmarshal(layout.ID, &sdk); e != nil {
			t.Fatal(e)
		}
		projected[i], _ = json.Marshal(sdk)
		if _, e := resultwire.NormalizeDiscoveryID([]byte("9007199254740993.0")); e == nil {
			t.Fatal("fraction accepted")
		}
	}
	if !bytes.Equal(projected[0], projected[1]) {
		t.Fatal("fixture does not exercise actual SDK float collision", projected)
	}
	for _, id := range []string{"null", "true", "{}", "[]", "9223372036854775808", "1e3"} {
		if _, e := resultwire.NormalizeDiscoveryID([]byte(id)); e == nil {
			t.Fatal("open ID domain", id)
		}
	}
	// An original raw message by itself cannot manufacture an active transport.
	g := &graphTransport{server: New(fakeExe, "test", nil), active: map[string]*graphCall{}}
	raw := json.RawMessage(`{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"name":"template_discover","arguments":{"task":"entity","maxBytes":2048}}}`)
	call := &graphCall{transport: g, raw: raw, id: json.RawMessage("9007199254740993"), ctx: context.Background(), ceiling: 2048}
	if discoverySDKIDMatches(call, projected[0]) {
		t.Fatal("detached raw message created ownership")
	}
	g.active[string(call.id)] = call
	if !discoverySDKIDMatches(call, projected[0]) {
		t.Fatal("actual active SDK projection not recognized")
	}
	g.active[string(call.id)] = &graphCall{}
	if discoverySDKIDMatches(call, projected[0]) {
		t.Fatal("replacement active pointer accepted")
	}
}

func TestTemplateDiscoveryCancellationClosedOriginalNotification(t *testing.T) {
	valid := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9007199254740993,"reason":"requested"}}`
	id, ok := discoveryCancellation([]byte(valid))
	if !ok || string(id) != "9007199254740993" {
		t.Fatal("exact original cancellation", string(id), ok)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"2.0"`, `"1.0"`, 1),
		strings.Replace(valid, `"requestId":9007199254740993`, `"requestId":9007199254740992,"requestId":9007199254740993`, 1),
		strings.Replace(valid, `"requested"`, `null`, 1),
		strings.Replace(valid, `"requested"`, `42`, 1),
		strings.Replace(valid, `"jsonrpc"`, `"id":1,"jsonrpc"`, 1),
		strings.Replace(valid, `"reason":"requested"`, `"reason":"requested","unknown":true`, 1),
		valid + ` {}`,
	} {
		if _, ok := discoveryCancellation([]byte(raw)); ok {
			t.Fatal("malformed cancellation accepted", raw)
		}
	}
}

// Separate observation command for intentionally regenerating proposed output
// contracts from the actual compiled registry. Acceptance tests still compare
// the checked-in files and all38 unchanged/new descriptors afterward.
func TestTemplateDiscoveryCaptureProposedContracts(t *testing.T) {
	dir := os.Getenv("TPLAITER_DISCOVERY_CONTRACT_CAPTURE")
	if dir == "" {
		t.Skip("explicit compiled contract observation")
	}
	s := New("/nonexistent", "test", nil)
	tools := s.MCP().ListTools()
	names := []string{}
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	list := []json.RawMessage{}
	for _, name := range names {
		raw, e := json.Marshal(tools[name].Tool)
		if e != nil {
			t.Fatal(e)
		}
		list = append(list, raw)
	}
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if e := encoder.Encode(list); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "tools.schema.actual.json"), b.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := discoveryDataSchema()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "discovery.schema.actual.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
}
