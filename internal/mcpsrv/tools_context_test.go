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

// Keep the existing shared oracle byte-for-byte intact while checking the
// complete union; its owner can incorporate the separately exported entry.
func TestContextPreservesSharedToolSurface(t *testing.T) {
	raw, err := os.ReadFile(toolsGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New("/nonexistent/tplaiter", "test", nil)
	var inherited []string
	for name := range s.MCP().ListTools() {
		if name != "context" {
			inherited = append(inherited, name)
		}
	}
	sort.Strings(inherited)
	if strings.Join(inherited, "\n")+"\n" != string(raw) {
		t.Fatal("context registration changed another owner's tool surface")
	}
	if len(inherited) != len(strings.Fields(string(raw))) {
		t.Fatalf("accepted public runtime surface: got %d tools", len(inherited))
	}
	t.Logf("accepted %d shared tools preserved exactly; context exported separately", len(inherited))
}
