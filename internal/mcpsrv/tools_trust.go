package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// ── trust ────────────────────────────────────────────────────────────────

func (s *Server) addTrustTools() {
	s.mcp.AddTool(mcp.NewTool(
		"trust_inspect",
		mcp.WithDescription("Check and return the pinned trust-profile binding (result/v1 trust.inspect; the binding is in data.binding)."),
		mcp.WithReadOnlyHintAnnotation(true),
		outputSchema(resultdto.OperationTrustInspect),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.callTrustInspect(ctx), nil
	}))
}
