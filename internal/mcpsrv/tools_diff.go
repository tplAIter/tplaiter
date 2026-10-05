package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

type diffArgs struct {
	Dir            string `json:"dir"`
	ProjectContext string `json:"projectContext"`
	ExitCode       bool   `json:"exitCode"`
}

func (s *Server) addDiffTools() {
	s.mcp.AddTool(mcp.NewTool("project_diff",
		mcp.WithDescription("Read-only offline diff against the authenticated signed baseline. Reports path and blockId independently; no link, adoption, update or execution."),
		mcp.WithString("dir", mcp.Description("Existing target and child working directory; must match the installed context root")),
		mcp.WithString("projectContext", mcp.Description("Authenticated installed context key")),
		mcp.WithBoolean("exitCode", mcp.DefaultBool(false), mcp.Description("Return finding status when drift exists")),
		mcp.WithReadOnlyHintAnnotation(true), mcp.WithDestructiveHintAnnotation(false), mcp.WithIdempotentHintAnnotation(true), mcp.WithOpenWorldHintAnnotation(false), outputSchema(resultdto.OperationProjectDiff),
	), mcp.NewTypedToolHandler(func(ctx context.Context, request mcp.CallToolRequest, a diffArgs) (*mcp.CallToolResult, error) {
		for key := range request.GetArguments() {
			if key != "dir" && key != "projectContext" && key != "exitCode" {
				return s.argumentFailure(resultdto.OperationProjectDiff, "arguments"), nil
			}
		}
		cwd, fail := s.workDir(resultdto.OperationProjectDiff, "dir", a.Dir)
		if fail != nil {
			return fail, nil
		}
		argv := []string{"diff", "--dir", cwd, "--offline=true"}
		if a.ProjectContext != "" {
			argv = append(argv, "--project-context", a.ProjectContext)
		}
		if a.ExitCode {
			argv = append(argv, "--exit-code")
		}
		return s.callStructured(ctx, resultdto.OperationProjectDiff, cwd, argv, shortCall), nil
	}))
}
