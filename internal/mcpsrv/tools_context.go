package mcpsrv

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// Add only this domain; shared tool registry/goldens belong to their owners.
func init() {
	toolRegistrars = append(toolRegistrars, (*Server).addContextTools)
	dataSchemas[resultdto.OperationContextQuery] = func() (json.RawMessage, error) { return json.RawMessage(`{"type":"object"}`), nil }
}

type contextToolArgs struct {
	Action         string             `json:"action"`
	ProjectContext string             `json:"projectContext,omitempty"`
	Dir            string             `json:"dir,omitempty"`
	Request        contextcmd.Request `json:"request,omitempty"`
}

func ContextFullSchema() (json.RawMessage, error) {
	input, err := schemaOf[contextToolArgs]()
	if err != nil {
		return nil, err
	}
	data, err := schemaOf[resultdto.ContextData]()
	if err != nil {
		return nil, err
	}
	output, err := resultdto.OperationSchema(resultdto.OperationContextQuery, data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Input  json.RawMessage `json:"input"`
		Output json.RawMessage `json:"output"`
	}{input, output})
}

func (s *Server) addContextTools() {
	s.mcp.AddTool(mcp.NewTool(
		"context",
		mcp.WithDescription("Read installed signed context with bounded local byte plans. Model window stays unknown. Actions discover/search/get/continue/plan; pull schema on demand."),
		mcp.WithString("action", mcp.Required(), mcp.Enum("discover", "search", "get", "continue", "plan", "schema")),
		mcp.WithString("projectContext", mcp.Description("Exact installed context key; default is registered")),
		mcp.WithString("dir", mcp.Description("Optional locator, must match the installed root")),
		mcp.WithObject("request", mcp.Description("Typed selectors/byte bounds; action=schema gives full contract")),
		mcp.WithReadOnlyHintAnnotation(true), outputSchema(resultdto.OperationContextQuery),
	), func(ctx context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Unlike default typed decoding, this rejects unknown fields and nested
		// window/reader/authority proposals rather than silently dropping them.
		raw, err := json.Marshal(call.GetArguments())
		if err != nil {
			return s.argumentFailure(resultdto.OperationContextQuery, "request"), nil //nolint:nilerr // MCP argument failures are typed tool results, not protocol errors
		}
		var a contextToolArgs
		if canonicaljson.DecodeStrict(raw, &a) != nil {
			return s.argumentFailure(resultdto.OperationContextQuery, "request"), nil //nolint:nilerr // MCP decoding failures are typed tool results, not protocol errors
		}
		switch a.Action {
		case "discover", "search", "get", "continue", "plan", "schema":
		default:
			return s.argumentFailure(resultdto.OperationContextQuery, "action"), nil
		}
		if a.Request.Action != "" || len(raw) > 16384 {
			return s.argumentFailure(resultdto.OperationContextQuery, "request"), nil
		}
		cwd := ""
		if a.Dir != "" {
			var failed *mcp.CallToolResult
			cwd, failed = s.workDir(resultdto.OperationContextQuery, "dir", a.Dir)
			if failed != nil {
				return failed, nil
			}
		}
		selectors, err := json.Marshal(a.Request)
		if err != nil {
			return s.argumentFailure(resultdto.OperationContextQuery, "request"), nil //nolint:nilerr // MCP argument failures are typed tool results, not protocol errors
		}
		argv := []string{"context", a.Action, "--request=" + string(selectors)}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context="+a.ProjectContext)
		}
		if cwd != "" {
			argv = append(argv, "--dir="+cwd)
		}
		return s.callStructured(ctx, resultdto.OperationContextQuery, cwd, argv, shortCall), nil
	})
	s.mcp.AddResourceTemplate(mcp.NewResourceTemplate("tplaiter://context/{projectContext}/{snapshot}/{id}", "signed context entry", mcp.WithTemplateDescription("Snapshot-addressed signed context; exact registered project key, no caller path"), mcp.WithTemplateMIMEType("application/json")), s.readContextResource)
}

func (s *Server) readContextResource(ctx context.Context, call mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	key, snapshot, id, err := contextcmd.ParseResourceURI(call.Params.URI)
	if err != nil {
		return nil, fmt.Errorf("%s", contextcmd.Invalid)
	}
	argv := []string{"context", "get", "--project-context=" + key, "--snapshot=" + snapshot, "--id=" + id, "--max-bytes=32768"}
	res, err := s.runCLI(ctx, "", append(argv, "--json"), s.timeout(shortCall))
	if failed(res, err) {
		code := transportCode(res, err)
		if code == "" {
			code = contextcmd.Stale
		}
		return nil, fmt.Errorf("%s", code)
	}
	env, err := resultdto.Decode([]byte(res.Stdout))
	if err != nil || env.Operation != resultdto.OperationContextQuery || env.Status != resultdto.StatusOK {
		return nil, fmt.Errorf("%s", contextcmd.Stale)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{URI: call.Params.URI, MIMEType: "application/json", Text: string(env.Data)}}, nil
}
