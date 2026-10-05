package mcpsrv

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestContextToolCompactSchemaAndOwnedExport(t *testing.T) {
	s := New("/nonexistent/tplaiter", "test", &execx.RecordingRunner{})
	tool := s.MCP().ListTools()["context"].Tool
	descriptor, err := json.Marshal(tool)
	if err != nil {
		t.Fatal(err)
	}
	full, err := ContextFullSchema()
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptor) >= len(full) {
		t.Fatal("descriptor repeats full schema")
	}
	schema := compileToolSchema(t, tool.RawOutputSchema)
	validateStructured(t, schema, s.argumentFailure(resultdto.OperationContextQuery, "request"), "argument")
	// Export only this new tool; shared golden entries are deliberately untouched.
	if path := os.Getenv("TPLAITER_C05_TOOL_EXPORT"); path != "" {
		if err = os.WriteFile(path, append(descriptor, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path+".full-schema.json", append(full, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("context tool descriptor=%d bytes; full on-demand schema=%d bytes", len(descriptor), len(full))
}

func TestContextToolRejectsUnknownWindowAndAuthority(t *testing.T) {
	runner := &execx.RecordingRunner{}
	s := New("/nonexistent/tplaiter", "test", runner)
	handler := s.MCP().ListTools()["context"].Handler
	for _, args := range []map[string]any{{"action": "plan", "request": map[string]any{"trustedWindow": 256000}}, {"action": "get", "request": map[string]any{"root": "/arbitrary"}}, {"action": "get", "window": 256000}, {"action": "continue", "request": map[string]any{"action": "get"}}} {
		request := mcp.CallToolRequest{}
		request.Params.Arguments = args
		result, err := handler(context.Background(), request)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("unknown input accepted: %+v %v", args, err)
		}
	}
	if len(runner.Calls) != 0 {
		t.Fatal("invalid context arguments spawned a child")
	}
}

// The shared golden is the complete union. Removing the two named additions
// must preserve the inherited 28 named tools.
func TestContextPreservesSharedToolSurface(t *testing.T) {
	raw, err := os.ReadFile(toolsGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var expected []string
	contextNames := 0
	projectLinkNames := 0
	for _, name := range strings.Fields(string(raw)) {
		switch name {
		case "context":
			contextNames++
		case "project_link":
			projectLinkNames++
		default:
			expected = append(expected, name)
		}
	}
	if contextNames != 1 || projectLinkNames != 1 || len(expected) != 28 {
		t.Fatalf("shared union must contain inherited 28 plus context and project_link: inherited=%d context=%d project_link=%d", len(expected), contextNames, projectLinkNames)
	}
	s := New("/nonexistent/tplaiter", "test", nil)
	tools := s.MCP().ListTools()
	if _, ok := tools["context"]; !ok {
		t.Fatal("registered union is missing context")
	}
	if _, ok := tools["project_link"]; !ok || len(tools) != 30 {
		t.Fatalf("registered union must contain inherited 28 plus context and project_link: tools=%d", len(tools))
	}
	var inherited []string
	for name := range tools {
		if name != "context" && name != "project_link" {
			inherited = append(inherited, name)
		}
	}
	sort.Strings(inherited)
	sort.Strings(expected)
	if strings.Join(inherited, "\n") != strings.Join(expected, "\n") {
		t.Fatal("context registration changed another owner's named tool surface")
	}
	t.Logf("inherited %d named tools preserved; context and project_link are the named additions", len(inherited))
}

func TestLocalPreviewAddsActionsKeepsNativeActions(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	tools := s.MCP().ListTools()
	if len(tools) != 30 {
		t.Fatal("tool inventory")
	}
	action := tools["context"].Tool.InputSchema.Properties["action"].(map[string]any)
	raw, _ := json.Marshal(action)
	for _, name := range []string{"discover", "search", "get", "continue", "plan", "schema", "preview-catalog", "preview-resource"} {
		if !strings.Contains(string(raw), `"`+name+`"`) {
			t.Fatal("action removed", name)
		}
	}
	if _, ok := tools["context"].Tool.InputSchema.Properties["preview"]; !ok {
		t.Fatal("typed preview input absent")
	}
}

func TestContextRootV2SchemaOnlyAmendsOwnedBody(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	before, e := json.Marshal(s.MCP().ListTools()["context"].Tool)
	if e != nil {
		t.Fatal(e)
	}
	full, e := ContextFullSchema()
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if e = json.Unmarshal(full, &doc); e != nil {
		t.Fatal(e)
	}
	// Compile the complete advertised schema, including both explicit body versions.
	raw, _ := json.Marshal(doc["output"])
	schema := compileToolSchema(t, raw)
	if schema == nil {
		t.Fatal("schema unavailable")
	}
	text := string(full)
	for _, version := range []string{"tplaiter.dev/context-root-selection/v1", resultdto.ContextRootV2, "tplaiter.dev/context-index-facts/v2"} {
		if !strings.Contains(text, version) {
			t.Fatal("version missing", version)
		}
	}
	after, _ := json.Marshal(s.MCP().ListTools()["context"].Tool)
	if string(before) != string(after) {
		t.Fatal("on-demand schema altered compact registration")
	}
	t.Log("both closed ROOT body versions advertised; compact context descriptor unchanged")
}
