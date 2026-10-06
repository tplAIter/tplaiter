// Package resultwire encodes the existing SDK representation without granting
// authority. Graph frame layouts are pure presentation inputs.
package resultwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"strconv"
	"strings"
)

const MaxSummaryLines = 12
const GraphFrameVersion = "tplaiter.dev/graph-mcp-frame/v1"

type GraphFrameLayout struct {
	APIVersion string          `json:"apiVersion"`
	ID         json.RawMessage `json:"normalizedID"`
	Ceiling    int             `json:"ceiling"`
}

func (l GraphFrameLayout) Validate() error {
	if l.APIVersion != GraphFrameVersion || l.Ceiling < 1024 || l.Ceiling > 32768 || len(l.ID) == 0 || len(l.ID) > 32768 {
		return errors.New("GRAPH_ARGUMENT_INVALID")
	}
	var id any
	if json.Unmarshal(l.ID, &id) != nil {
		return errors.New("GRAPH_ARGUMENT_INVALID")
	}
	switch id.(type) {
	case string, float64:
	default:
		return errors.New("GRAPH_ARGUMENT_INVALID")
	}
	raw, err := json.Marshal(id)
	if err != nil || !bytes.Equal(raw, l.ID) {
		return errors.New("GRAPH_ARGUMENT_INVALID")
	}
	return nil
}
func (l GraphFrameLayout) RequestID() mcp.RequestId {
	var id any
	_ = json.Unmarshal(l.ID, &id)
	return mcp.NewRequestId(id)
}
func EncodeGraphFrame(l GraphFrameLayout) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(l)
	return base64.RawURLEncoding.EncodeToString(raw), err
}
func DecodeGraphFrame(encoded string) (GraphFrameLayout, error) {
	var l GraphFrameLayout
	if len(encoded) > 65536 {
		return l, errors.New("GRAPH_ARGUMENT_INVALID")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return l, err
	}
	if err = canonicaljson.DecodeStrict(raw, &l); err != nil {
		return l, err
	}
	return l, l.Validate()
}

// Frame uses the SDK's actual response type and standard serializer plus newline.
func Frame(id mcp.RequestId, result *mcp.CallToolResult) ([]byte, error) {
	raw, err := json.Marshal(mcp.NewJSONRPCResultResponse(id, result))
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
func Structured(env resultdto.Result, isError bool) *mcp.CallToolResult {
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		return mcp.NewToolResultError("MCP_CONTRACT_INVALID")
	}
	var structured map[string]any
	if err := json.Unmarshal(raw, &structured); err != nil {
		return mcp.NewToolResultError("MCP_CONTRACT_INVALID")
	}
	out := mcp.NewToolResultStructured(structured, Summary(env))
	out.IsError = isError
	return out
}

// compactSummary renders at most MaxSummaryLines lines: the outcome, the
// counters, and the diagnostic codes. The full envelope is always in the
// structured content.
func Summary(env resultdto.Result) string {
	lines := []string{string(env.Operation) + ": " + string(env.Status)}
	if env.Project != nil {
		lines = append(lines, "project: "+env.Project.Root)
	}
	if n := len(env.Changes); n > 0 || env.Summary.FilesChanged > 0 || env.Summary.Conflicts > 0 {
		lines = append(lines, "changes: "+strconv.Itoa(n)+", files changed: "+strconv.Itoa(env.Summary.FilesChanged)+", conflicts: "+strconv.Itoa(env.Summary.Conflicts))
	}
	for i, d := range env.Diagnostics {
		if len(lines) >= MaxSummaryLines-2 {
			lines = append(lines, "… "+strconv.Itoa(len(env.Diagnostics)-i)+" more diagnostic(s)")
			break
		}
		lines = append(lines, d.Severity+" "+d.Code+": "+d.Message)
	}
	if len(env.Data) > 0 && len(lines) < MaxSummaryLines {
		lines = append(lines, "data: see structured content")
	}
	return strings.Join(lines, "\n")
}
