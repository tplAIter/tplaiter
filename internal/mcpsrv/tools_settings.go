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
		mcp.WithDescription("Показать текущие значения настроек проекта (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
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
		mcp.WithDescription("Изменить настройки проекта (dir) 3-way merge на текущей версии шаблона. Применяется без подтверждения (--yes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithObject("values", mcp.Required(), mcp.Description("Новые значения: группа→значение")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a settingsSetArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvSettingsSet(a.Values), longTimeout), nil
	}))
}
