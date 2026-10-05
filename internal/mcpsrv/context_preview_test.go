package mcpsrv

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/execx"
)

func TestLocalPreviewFullEnvelopeAndHostCorrelation(t *testing.T) {
	frames := &previewFrames{}
	meta := &mcp.Meta{}
	result := mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "observed bytes"}}}
	if frames.fits(meta, result, 32768) {
		t.Fatal("caller correlation manufactured accounting")
	}
	id := json.RawMessage(`"bounded-correlation"`)
	frames.ids.Store(meta, id)
	encoded, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{"2.0", id, result})
	if frames.fits(meta, result, len(encoded)) || !frames.fits(meta, result, len(encoded)+1) {
		t.Fatal("full JSON-RPC envelope/newline not counted")
	}
	frames.ids.Store(meta, json.RawMessage(`"a-much-longer-correlation-string"`))
	if frames.fits(meta, result, len(encoded)+1) {
		t.Fatal("caller ID omitted from budget")
	}
}

func TestLocalPreviewRejectsEndpointAndNativeMix(t *testing.T) {
	runner := &execx.RecordingRunner{}
	s := New("/nonexistent", "test", runner)
	handler := s.MCP().ListTools()["context"].Handler
	for _, args := range []map[string]any{
		{"action": "preview-catalog", "preview": map[string]any{"registrationID": "local", "socketPath": "/caller"}},
		{"action": "preview-catalog", "preview": map[string]any{"registrationID": "local"}, "request": map[string]any{}},
		{"action": "discover", "preview": map[string]any{"registrationID": "local"}},
		{"action": "preview-resource", "preview": map[string]any{"registrationID": "local"}},
	} {
		req := mcp.CallToolRequest{}
		req.Params.Arguments = args
		res, err := handler(context.Background(), req)
		if err != nil || res == nil || !res.IsError {
			t.Fatal("invalid mixed authority request", args)
		}
	}
	if len(runner.Calls) != 0 {
		t.Fatal("invalid input reached installed child")
	}
}
