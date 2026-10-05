package mcpsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// Correlation bytes come only from server hooks. A caller's _meta cannot mint
// the pointer key recorded here. This is byte accounting, not read authority.
type previewFrames struct{ ids sync.Map }

func (s *Server) installPreviewFrames() *previewFrames {
	frames := &previewFrames{}
	hooks := s.mcp.GetHooks()
	if hooks == nil {
		hooks = &server.Hooks{}
		server.WithHooks(hooks)(s.mcp)
	}
	hooks.AddBeforeCallTool(func(_ context.Context, id any, req *mcp.CallToolRequest) {
		if req.Params.Name != "context" {
			return
		}
		meta := &mcp.Meta{}
		if req.Params.Meta != nil {
			*meta = *req.Params.Meta
		}
		req.Params.Meta = meta
		raw, err := json.Marshal(id)
		if err == nil {
			frames.ids.Store(meta, json.RawMessage(raw))
		}
	})
	hooks.AddAfterCallTool(func(_ context.Context, _ any, req *mcp.CallToolRequest, _ any) { frames.ids.Delete(req.Params.Meta) })
	hooks.AddBeforeReadResource(func(_ context.Context, id any, req *mcp.ReadResourceRequest) {
		if !strings.HasPrefix(req.Params.URI, "tplaiter://context-preview/") {
			return
		}
		meta := &mcp.Meta{}
		if req.Params.Meta != nil {
			*meta = *req.Params.Meta
		}
		req.Params.Meta = meta
		raw, err := json.Marshal(id)
		if err == nil {
			frames.ids.Store(meta, json.RawMessage(raw))
		}
	})
	hooks.AddAfterReadResource(func(_ context.Context, _ any, req *mcp.ReadResourceRequest, _ *mcp.ReadResourceResult) {
		frames.ids.Delete(req.Params.Meta)
	})
	return frames
}

func (f *previewFrames) fits(meta *mcp.Meta, result any, budget int) bool {
	raw, ok := f.ids.Load(meta)
	if !ok {
		return false
	}
	packet := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{"2.0", raw.(json.RawMessage), result}
	encoded, err := json.Marshal(packet)
	return err == nil && len(encoded)+1 <= budget
}

func (s *Server) callLocalPreview(ctx context.Context, a contextToolArgs, call mcp.CallToolRequest, frames *previewFrames) *mcp.CallToolResult {
	req := *a.Preview
	if err := contextcmd.NormalizeLocalPreview(a.Action, &req); err != nil {
		return s.argumentFailure(resultdto.OperationContextQuery, "preview")
	}
	// Missing protocol accounting context refuses before opening a host. Direct
	// handler tests cannot pretend to be a complete installed MCP invocation.
	if _, ok := frames.ids.Load(call.Params.Meta); !ok {
		return s.argumentFailure(resultdto.OperationContextQuery, "preview")
	}
	selectors, err := json.Marshal(req)
	if err != nil {
		return s.argumentFailure(resultdto.OperationContextQuery, "preview")
	}
	argv := []string{"context", a.Action, "--request=" + string(selectors)}
	if a.ProjectContext != "" {
		argv = append(argv, "--project-context="+a.ProjectContext)
	}
	cwd := ""
	if a.Dir != "" {
		var failure *mcp.CallToolResult
		cwd, failure = s.workDir(resultdto.OperationContextQuery, "dir", a.Dir)
		if failure != nil {
			return failure
		}
		argv = append(argv, "--dir="+cwd)
	}
	result := s.callStructured(ctx, resultdto.OperationContextQuery, cwd, argv, shortCall)
	if !result.IsError && !frames.fits(call.Params.Meta, result, req.MaxBytes) {
		return s.argumentFailure(resultdto.OperationContextQuery, "preview byte budget")
	}
	return result
}

func (s *Server) readLocalPreviewResource(ctx context.Context, call mcp.ReadResourceRequest, frames *previewFrames) ([]mcp.ResourceContents, error) {
	key, req, err := contextcmd.ParsePreviewResourceURI(call.Params.URI)
	if err != nil {
		return nil, fmt.Errorf("%s", contextcmd.Invalid)
	}
	if _, ok := frames.ids.Load(call.Params.Meta); !ok {
		return nil, fmt.Errorf("%s", contextcmd.Invalid)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	res, err := s.runCLI(ctx, "", []string{"context", "preview-resource", "--project-context=" + key, "--request=" + string(raw), "--json"}, s.timeout(shortCall))
	if failed(res, err) {
		return nil, fmt.Errorf("%s", contextcmd.Stale)
	}
	envelope, err := resultdto.Decode([]byte(res.Stdout))
	if err != nil || envelope.Operation != resultdto.OperationContextQuery || envelope.Status != resultdto.StatusOK {
		return nil, fmt.Errorf("%s", contextcmd.Stale)
	}
	contents := []mcp.ResourceContents{mcp.TextResourceContents{URI: call.Params.URI, MIMEType: "application/json", Text: string(envelope.Data)}}
	if !frames.fits(call.Params.Meta, mcp.ReadResourceResult{Contents: contents}, req.MaxBytes) {
		return nil, fmt.Errorf("%s", contextcmd.Budget)
	}
	return contents, nil
}
