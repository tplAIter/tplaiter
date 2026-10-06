package mcpsrv

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
)

func init() { dataSchemas[resultdto.OperationSemanticPreview] = semanticDataSchema }
func semanticDataSchema() (json.RawMessage, error) {
	raw, e := schemaOf[resultdto.SemanticPreviewData]()
	if e != nil {
		return nil, e
	}
	var schema map[string]any
	if e = json.Unmarshal(raw, &schema); e != nil {
		return nil, e
	}
	var walk func(map[string]any)
	walk = func(node map[string]any) {
		if properties, ok := node["properties"].(map[string]any); ok {
			for key, v := range properties {
				child, ok := v.(map[string]any)
				if !ok {
					continue
				}
				if key == "before" || key == "after" {
					if _, isArray := child["items"]; isArray {
						properties[key] = map[string]any{"type": "string", "pattern": `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`}
						continue
					}
				}
				walk(child)
			}
		}
		for _, key := range []string{"items", "$defs", "definitions"} {
			if child, ok := node[key].(map[string]any); ok {
				if key == "items" {
					walk(child)
				} else {
					for _, v := range child {
						if m, ok := v.(map[string]any); ok {
							walk(m)
						}
					}
				}
			}
		}
	}
	walk(schema)
	return json.Marshal(schema)
}

type semanticArgs struct {
	Dir            string `json:"dir"`
	ProjectContext string `json:"projectContext"`
	Input          string `json:"input"`
	MaxBytes       int    `json:"maxBytes"`
}

func semanticArgv(a semanticArgs) []string {
	argv := []string{"semantic", "preview", "--input", a.Input, "--max-bytes", strconv.Itoa(a.MaxBytes)}
	if a.Dir != "" {
		argv = append(argv, "--dir", a.Dir)
	}
	if a.ProjectContext != "" {
		argv = append(argv, "--project-context", a.ProjectContext)
	}
	return argv
}
func (s *Server) addSemanticTools() {
	tool := mcp.NewTool("semantic_preview", mcp.WithDescription("Observe four bounded original-token Go edit intents with complete before/after images and diff. Syntax only; compiler verification and Apply are unavailable. Captured child observation does not hold a source lease through final SDK delivery."), mcp.WithString("dir", mcp.Required()), mcp.WithString("projectContext"), mcp.WithString("input", mcp.Required(), mcp.Description("Closed semantic-preview/v1 request file locator")), mcp.WithNumber("maxBytes"), outputSchema(resultdto.OperationSemanticPreview))
	tool.Annotations.ReadOnlyHint = ptrGraphTrue()
	s.mcp.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		raw, e := json.Marshal(req.Params.Arguments)
		var a semanticArgs
		if e != nil || canonicaljson.DecodeStrict(raw, &a) != nil {
			return s.argumentFailure(resultdto.OperationSemanticPreview, "arguments"), nil
		}
		if a.MaxBytes == 0 {
			a.MaxBytes = 32768
		}
		call, ok := ctx.Value(graphCallKey{}).(*graphCall)
		if !ok || call == nil || !call.sdkBound || call.transport.server != s {
			return s.argumentFailure(resultdto.OperationSemanticPreview, "semantic transport"), nil
		}
		cwd, failure := s.workDir(resultdto.OperationSemanticPreview, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		layout := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: call.id, Ceiling: call.ceiling}
		encoded, e := resultwire.EncodeGraphFrame(layout)
		if e != nil {
			return s.argumentFailure(resultdto.OperationSemanticPreview, "layout"), nil
		}
		out := s.callStructured(call.ctx, resultdto.OperationSemanticPreview, cwd, append(semanticArgv(a), "--graph-mcp-frame", encoded), shortCall)
		if out.StructuredContent != nil {
			b, _ := json.Marshal(out.StructuredContent)
			var envelope resultdto.Result
			if json.Unmarshal(b, &envelope) != nil {
				return mcp.NewToolResultError("SEMANTIC_RESULT_INVALID"), nil
			}
			if len(envelope.Data) > 0 {
				if _, e = resultdto.DecodeSemanticPreviewData(envelope.Data); e != nil {
					return mcp.NewToolResultError("SEMANTIC_RESULT_INVALID"), nil
				}
			}
		}
		call.expected, _ = resultwire.Frame(layout.RequestID(), out)
		return out, nil
	})
}

// semanticInput routes only this new operation through the existing SDK-owned
// graph dispatcher and context-aware final output gate. Other bytes are forwarded
// unchanged. Its layout is presentation data and cannot admit a source.
type semanticInput struct {
	input   *bufio.Reader
	graph   *graphTransport
	pending []byte
}

func (s *semanticInput) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		frame, e := readTransportFrame(s.graph.ctx, s.input)
		if e == errTransportFrameLimit {
			refusal := s.graph.writeRefusal()
			s.graph.cancel()
			if s.graph.stopStdio != nil {
				s.graph.stopStdio()
			}
			if refusal != nil {
				return 0, refusal
			}
			return 0, errTransportFrameHandled
		}
		line := frame.raw
		if len(line) == 0 {
			return 0, e
		}
		var route struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
			Params  struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &route) != nil || route.Method != "tools/call" || route.Params.Name != "semantic_preview" {
			s.pending = line
			break
		}
		g := s.graph
		id, err := json.Marshal(route.ID)
		var a semanticArgs
		inputErr := canonicaljson.DecodeStrict(route.Params.Arguments, &a)
		if a.MaxBytes == 0 {
			a.MaxBytes = 32768
		}
		layout := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: id, Ceiling: a.MaxBytes}
		invalid := len(line) > 2<<20 || route.JSONRPC != "2.0" || err != nil || inputErr != nil || a.Input == "" || layout.Validate() != nil || g.session == nil
		if !invalid {
			_, err = canonicaljson.Canonicalize(line)
			invalid = err != nil
		}
		if !invalid {
			frame, err := resultwire.Frame(layout.RequestID(), mcp.NewToolResultError("SEMANTIC_OUTPUT_BUDGET"))
			invalid = err != nil || len(frame) > a.MaxBytes
		}
		if invalid {
			if e = g.writeRefusal(); e != nil {
				return 0, e
			}
			continue
		}
		g.mu.Lock()
		if g.closed || len(g.active) >= 64 || g.active[string(id)] != nil {
			g.mu.Unlock()
			if e = g.writeRefusal(); e != nil {
				return 0, e
			}
			continue
		}
		owned, cancel := context.WithTimeout(g.session, g.server.timeout(shortCall))
		stop := context.AfterFunc(g.ctx, cancel)
		call := &graphCall{transport: g, raw: append(json.RawMessage{}, line...), id: append(json.RawMessage{}, id...), ctx: owned, cancel: cancel, ceiling: a.MaxBytes}
		g.active[string(id)] = call
		g.workers.Add(1)
		g.mu.Unlock()
		go func() { defer stop(); g.dispatch(call) }()
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

var _ io.Reader = (*semanticInput)(nil)
