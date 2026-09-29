package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── miscellaneous (projects / env) ───────────────────────────────────────────

type envSetupArgs struct {
	Dir  string `json:"dir"`
	Name string `json:"name"`
	Yes  bool   `json:"yes"`
}

func (s *Server) addMiscTools() {
	s.mcp.AddTool(mcp.NewTool(
		"projects_list",
		mcp.WithDescription("List of projects in the local registry (path, template, time, status)."),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationProjectsList),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.callStructured(ctx, resultdto.OperationProjectsList, "", argvProjectsList(), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"env_setup",
		mcp.WithDescription("Execute an Ansible playbook for the project environment (dir). Ansible setup is confirmed automatically (yes is always true)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("name", mcp.Description("Playbook name (default: setup)")),
		mcp.WithBoolean("yes", mcp.Required(), mcp.Description("Force confirmation — always true"), mcp.DefaultBool(true)),
		outputSchema(resultdto.OperationEnvSetup),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a envSetupArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationEnvSetup, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationEnvSetup, cwd, argvEnvSetup(a.Name), longCall), nil
	}))
}
