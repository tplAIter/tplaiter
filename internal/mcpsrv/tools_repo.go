package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── repo ─────────────────────────────────────────────────────────────────

type repoAddArgs struct {
	Alias  string `json:"alias"`
	URL    string `json:"url"`
	Branch string `json:"branch"`
}

type repoUpdateArgs struct {
	Alias string `json:"alias"`
}

type repoRemoveArgs struct {
	Alias string `json:"alias"`
}

func (s *Server) addRepoTools() {
	s.mcp.AddTool(mcp.NewTool(
		"repo_add",
		mcp.WithDescription("Добавить git-репозиторий шаблонов (helm-модель). Токен НЕ передаётся через агента: приватные репозитории должен предварительно авторизовать человек."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Короткий алиас репозитория")),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL git-репозитория")),
		mcp.WithString("branch", mcp.Description("Ветка по умолчанию (опционально)")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoAddArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoAdd(a.Alias, a.URL, a.Branch), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_list",
		mcp.WithDescription("Список добавленных репозиториев шаблонов (алиас, URL, тип, число шаблонов, время обновления)."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_update",
		mcp.WithDescription("git fetch + переиндексация всех репозиториев шаблонов или одного по алиасу."),
		mcp.WithString("alias", mcp.Description("Алиас репозитория; пусто — обновить все")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoUpdateArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoUpdate(a.Alias), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_remove",
		mcp.WithDescription("Удалить репозиторий шаблонов из локального состояния."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Алиас удаляемого репозитория")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoRemoveArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoRemove(a.Alias), defaultTimeout), nil
	}))
}
