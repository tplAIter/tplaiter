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
		mcp.WithDescription("Catalog of templates from added repositories with filters."),
		mcp.WithString("repo", mcp.Description("Filter by repository alias (exact match)")),
		mcp.WithString("name", mcp.Description("Filter by template name substring")),
		mcp.WithArray("labels", mcp.Description("Filters by labels group=value (AND semantics)"),
			mcp.Items(map[string]any{"type": "string"})),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateListArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateList(a.Repo, a.Name, a.Labels), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"template_show",
		mcp.WithDescription("Metadata, settings tree, commands, and documentation of template by reference (repo/name@version or short name)."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Template reference: repo/name@version or short name")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateShowArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateShow(a.Ref), defaultTimeout), nil
	}))
}
