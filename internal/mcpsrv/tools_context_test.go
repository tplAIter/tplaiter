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

// The shared golden is the complete union. Removing only context must preserve
// the inherited 28 named tools, and context must be the single added name.
func TestContextPreservesSharedToolSurface(t *testing.T) {
	raw, err := os.ReadFile(toolsGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var expected []string
	contextNames := 0
	for _, name := range strings.Fields(string(raw)) {
		if name == "context" {
			contextNames++
			continue
		}
		expected = append(expected, name)
	}
	if contextNames != 1 || len(expected) != 28 {
		t.Fatalf("shared union must contain inherited 28 plus exactly one context: inherited=%d context=%d", len(expected), contextNames)
	}
	s := New("/nonexistent/tplaiter", "test", nil)
	tools := s.MCP().ListTools()
	if _, ok := tools["context"]; !ok || len(tools) != 29 {
		t.Fatalf("registered union must contain inherited 28 plus context: tools=%d", len(tools))
	}
	var inherited []string
	for name := range tools {
		if name != "context" {
			inherited = append(inherited, name)
		}
	}
	sort.Strings(inherited)
	sort.Strings(expected)
	if strings.Join(inherited, "\n") != strings.Join(expected, "\n") {
		t.Fatal("context registration changed another owner's named tool surface")
	}
	t.Logf("inherited %d named tools preserved; context is the only added name", len(inherited))
}
