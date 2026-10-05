package mcpsrv

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// Named shared test entry only; golden updates are handed off to primary.
func init() {
	toolOperations["project_link"] = []resultdto.Operation{resultdto.OperationProjectLink, resultdto.OperationProjectAdopt}
}
func TestLinkToolRegistersExactlyOneClosedActionSurface(t *testing.T) {
	tools := New("/nonexistent/tplaiter", "test", nil).MCP().ListTools()
	tool, ok := tools["project_link"]
	if !ok {
		t.Fatal("missing link tool")
	}
	action := tool.Tool.InputSchema.Properties["action"].(map[string]any)
	values, ok := action["enum"].([]string)
	if !ok || len(values) != 2 || values[0] != "link" || values[1] != "adopt" {
		t.Fatalf("action schema %+v", action)
	}
	// Export only owned named entries for the primary's shared schema/golden merge.
	if path := os.Getenv("TPLAITER_LINK_TOOL_EXPORT"); path != "" {
		raw, err := json.Marshal(tool.Tool)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := schemaOf[resultdto.ProjectLinkData]()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path+".data-schema.json", append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists := tools["project_adopt"]; exists {
		t.Fatal("unexpected second tool")
	}
}
