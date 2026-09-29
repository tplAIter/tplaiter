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
		mcp.WithDescription("Добавить Temporal service-action в go-workspace проект и зарегистрировать его в go.work. Выполняется полностью неинтерактивно."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Корень workspace-проекта или вложенный каталог внутри него")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя нового сервиса-action")),
		mcp.WithString("module", mcp.Description("Go module сервиса; по умолчанию <module workspace>/services/<slug>")),
		mcp.WithObject("set", mcp.Description("Настройки шаблона сервиса: группа→значение; workflow=true форсируется CLI")),
		mcp.WithBoolean("defaults", mcp.Description("Взять значения по умолчанию для незаданных групп"), mcp.DefaultBool(true)),
		mcp.WithBoolean("noHooks", mcp.Description("Не запускать hooks.postCreate"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Не проверять инструменты окружения"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Порт сервиса; 0 — использовать значение шаблона")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a workspaceAddServiceArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvWorkspaceAddService(a.Name, a.Module, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.Port), longTimeout), nil
	}))
}
