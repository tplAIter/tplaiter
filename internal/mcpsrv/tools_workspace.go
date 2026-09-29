package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── workspace ─────────────────────────────────────────────────────────────

type workspaceAddServiceArgs struct {
	Dir         string            `json:"dir"`
	Name        string            `json:"name"`
	Module      string            `json:"module"`
	Set         map[string]string `json:"set"`
	Defaults    bool              `json:"defaults"`
	NoHooks     bool              `json:"noHooks"`
	NoDepsCheck bool              `json:"noDepsCheck"`
	Port        int               `json:"port"`
}

func (s *Server) addWorkspaceTools() {
	s.mcp.AddTool(mcp.NewTool(
		"workspace_add_service",
		mcp.WithDescription("Add a Temporal service-action to a go-workspace project and register it in go.work. Executed completely non-interactively."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Root of workspace-project or a nested directory inside it")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of new service-action")),
		mcp.WithString("module", mcp.Description("Go module of service; default <workspace module>/services/<slug>")),
		mcp.WithObject("set", mcp.Description("Service template settings: group→value; workflow=true is forced by CLI")),
		mcp.WithBoolean("defaults", mcp.Description("Use default values for unspecified groups"), mcp.DefaultBool(true)),
		mcp.WithBoolean("noHooks", mcp.Description("Don't run hooks.postCreate"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Don't check environment tools"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Service port; 0 — use template value")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a workspaceAddServiceArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvWorkspaceAddService(a.Name, a.Module, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.Port), longTimeout), nil
	}))
}
