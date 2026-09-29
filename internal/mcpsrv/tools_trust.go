package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// ── trust ────────────────────────────────────────────────────────────────

func (s *Server) addTrustTools() {
	s.mcp.AddTool(mcp.NewTool(
		"trust_inspect",
		mcp.WithDescription("Check and return the pinned trust-profile binding as JSON."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTrustInspect(), defaultTimeout), nil
	}))
}
