package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── settings ───────────────────────────────────────────────────────────────

type settingsSetArgs struct {
	Dir    string            `json:"dir"`
	Values map[string]string `json:"values"`
}

func (s *Server) addSettingsTools() {
	s.mcp.AddTool(mcp.NewTool(
		"settings_list",
		mcp.WithDescription("Show current values of project settings (dir) as result/v1 settings.show."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationSettingsShow),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationSettingsShow, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationSettingsShow, cwd, argvSettingsList(), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"settings_set",
		mcp.WithDescription("Change project (dir) settings using 3-way merge on current template version. Applied without confirmation (--yes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Project directory")),
		mcp.WithObject("values", mcp.Required(), mcp.Description("New values: group→value")),
		outputSchema(resultdto.OperationSettingsSet),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a settingsSetArgs) (*mcp.CallToolResult, error) {
		cwd, failure := s.workDir(resultdto.OperationSettingsSet, "dir", a.Dir)
		if failure != nil {
			return failure, nil
		}
		return s.callStructured(ctx, resultdto.OperationSettingsSet, cwd, argvSettingsSet(a.Values), longCall), nil
	}))
}
