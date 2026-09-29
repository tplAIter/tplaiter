package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── template ─────────────────────────────────────────────────────────────

type templateListArgs struct {
	Repo   string   `json:"repo"`
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

type templateShowArgs struct {
	Ref string `json:"ref"`
}

func (s *Server) addTemplateTools() {
	s.mcp.AddTool(mcp.NewTool(
		"template_list",
		mcp.WithDescription("Каталог шаблонов добавленных репозиториев с фильтрами."),
		mcp.WithString("repo", mcp.Description("Фильтр по алиасу репозитория (точное совпадение)")),
		mcp.WithString("name", mcp.Description("Фильтр по подстроке имени шаблона")),
		mcp.WithArray("labels", mcp.Description("Фильтры по лейблам group=value (семантика AND)"),
			mcp.Items(map[string]any{"type": "string"})),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateListArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateList(a.Repo, a.Name, a.Labels), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"template_show",
		mcp.WithDescription("Метаданные, дерево настроек, команды и документация шаблона по ссылке ref (repo/name@version или короткая name)."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Ссылка на шаблон: repo/name@version или короткая name")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateShowArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateShow(a.Ref), defaultTimeout), nil
	}))
}
