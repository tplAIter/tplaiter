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
		mcp.WithDescription("Список проектов локального реестра (путь, шаблон, время, статус)."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvProjectsList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"env_setup",
		mcp.WithDescription("Запустить ansible-плейбук окружения проекта (dir). Установка ansible подтверждается автоматически (yes всегда true)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithString("name", mcp.Description("Имя плейбука (по умолчанию setup)")),
		mcp.WithBoolean("yes", mcp.Required(), mcp.Description("Форсирующее подтверждение — всегда true"), mcp.DefaultBool(true)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a envSetupArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvEnvSetup(a.Name), longTimeout), nil
	}))
}
