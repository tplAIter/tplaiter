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
		mcp.WithDescription("Self-test template repository for edge case combinations. Failure returns a non-zero exit code (isError)."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Template repository root")),
		mcp.WithString("combo", mcp.Description("Filter by combination name (exact match)")),
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
		mcp.WithDescription("Create a template repository with full tooling (manifest, files/, generators, ai-config, CI)."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of new template")),
		mcp.WithString("dir", mcp.Description("Target repository directory (created; default ./<name>)")),
		mcp.WithBoolean("multi", mcp.Description("Multi-repository (repo.manifest.yaml + template in subdirectory)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a initTemplateArgs) (*mcp.CallToolResult, error) {
		dir, err := resolveTargetDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, "", argvInitTemplate(a.Name, dir, a.Multi), longTimeout), nil
	}))
}
