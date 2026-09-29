package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
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
		outputSchema(resultdto.OperationRepoAdd),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoAddArgs) (*mcp.CallToolResult, error) {
		return s.callStructured(ctx, resultdto.OperationRepoAdd, "", argvRepoAdd(a.Alias, a.URL, a.Branch), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_list",
		mcp.WithDescription("List of added template repositories (alias, URL, type, number of templates, update time)."),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationRepoList),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.callStructured(ctx, resultdto.OperationRepoList, "", argvRepoList(), shortCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_update",
		mcp.WithDescription("git fetch + reindexing all template repositories or one by alias."),
		mcp.WithString("alias", mcp.Description("Repository alias; empty — update all")),
		outputSchema(resultdto.OperationRepoUpdate),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoUpdateArgs) (*mcp.CallToolResult, error) {
		return s.callStructured(ctx, resultdto.OperationRepoUpdate, "", argvRepoUpdate(a.Alias), longCall), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_remove",
		mcp.WithDescription("Remove a template repository from local state."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Alias of repository to remove")),
		outputSchema(resultdto.OperationRepoRemove),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoRemoveArgs) (*mcp.CallToolResult, error) {
		return s.callStructured(ctx, resultdto.OperationRepoRemove, "", argvRepoRemove(a.Alias), shortCall), nil
	}))
}
