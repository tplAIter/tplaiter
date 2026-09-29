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
		mcp.WithDescription("Add a git repository for templates (Helm-style). Token is NOT passed through the agent: private repositories must be authorized by a person in advance."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Short repository alias")),
		mcp.WithString("url", mcp.Required(), mcp.Description("Git repository URL")),
		mcp.WithString("branch", mcp.Description("Default branch (optional)")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoAddArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoAdd(a.Alias, a.URL, a.Branch), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_list",
		mcp.WithDescription("List of added template repositories (alias, URL, type, number of templates, update time)."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_update",
		mcp.WithDescription("git fetch + reindexing all template repositories or one by alias."),
		mcp.WithString("alias", mcp.Description("Repository alias; empty — update all")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoUpdateArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoUpdate(a.Alias), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_remove",
		mcp.WithDescription("Remove a template repository from local state."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Alias of repository to remove")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoRemoveArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoRemove(a.Alias), defaultTimeout), nil
	}))
}
