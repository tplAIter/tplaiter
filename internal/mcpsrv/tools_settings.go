package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── settings ───────────────────────────────────────────────────────────────

type settingsSetArgs struct {
	Dir    string            `json:"dir"`
	Values map[string]string `json:"values"`
}

func (s *Server) addSettingsTools() {
	s.mcp.AddTool(mcp.NewTool(
		"settings_list",
		mcp.WithDescription("Show current values of project settings (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvSettingsList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"settings_set",
		mcp.WithDescription("Change project (dir) settings using 3-way merge on current template version. Applied without confirmation (--yes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithObject("values", mcp.Required(), mcp.Description("New values: group→value")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a settingsSetArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvSettingsSet(a.Values), longTimeout), nil
	}))
}
