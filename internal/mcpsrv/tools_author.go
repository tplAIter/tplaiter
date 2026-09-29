package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── template-author tools (lint / init-template) ─────────────────────────────

type lintTemplateArgs struct {
	Path  string `json:"path"`
	Combo string `json:"combo"`
}

type initTemplateArgs struct {
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Multi bool   `json:"multi"`
}

func (s *Server) addTemplateAuthorTools() {
	s.mcp.AddTool(mcp.NewTool(
		"lint_template",
		mcp.WithDescription("Селфтест репозитория шаблона по угловым комбинациям настроек. Провал даёт ненулевой код возврата (isError)."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Корень репозитория шаблона")),
		mcp.WithString("combo", mcp.Description("Фильтр по имени комбинации (точное совпадение)")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a lintTemplateArgs) (*mcp.CallToolResult, error) {
		path, err := resolveWorkDir(a.Path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, "", argvLintTemplate(path, a.Combo), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"init_template",
		mcp.WithDescription("Создать репозиторий шаблона со всем инструментарием (манифест, files/, генераторы, ai-config, CI)."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя нового шаблона")),
		mcp.WithString("dir", mcp.Description("Целевой каталог репозитория (создаётся; по умолчанию ./<name>)")),
		mcp.WithBoolean("multi", mcp.Description("Multi-репозиторий (repo.manifest.yaml + шаблон в подкаталоге)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a initTemplateArgs) (*mcp.CallToolResult, error) {
		dir, err := resolveTargetDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, "", argvInitTemplate(a.Name, dir, a.Multi), longTimeout), nil
	}))
}
