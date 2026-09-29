package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
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
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvProjectsList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"env_setup",
		mcp.WithDescription("Execute an Ansible playbook for the project environment (dir). Ansible setup is confirmed automatically (yes is always true)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithString("name", mcp.Description("Playbook name (default: setup)")),
		mcp.WithBoolean("yes", mcp.Required(), mcp.Description("Force confirmation — always true"), mcp.DefaultBool(true)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a envSetupArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvEnvSetup(a.Name), longTimeout), nil
	}))
}
