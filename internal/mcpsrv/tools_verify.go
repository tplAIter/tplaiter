package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

type readonlyVerifyArgs struct {
	Dir            string `json:"dir"`
	TargetDir      string `json:"targetDir"`
	ProjectContext string `json:"projectContext"`
	Offline        *bool  `json:"offline"`
}

func (s *Server) addVerifyTools() {
	for _, entry := range []struct {
		name string
		op   resultdto.Operation
		argv []string
	}{
		{"project_verify", resultdto.OperationProjectVerify, []string{"verify"}},
		{"project_check", resultdto.OperationProjectCheck, []string{"check"}},
		{"deps_verify", resultdto.OperationDepsVerify, []string{"deps", "verify"}},
	} {
		s.mcp.AddTool(mcp.NewTool(
			entry.name,
			mcp.WithDescription("Read-only offline verification using an authenticated installed project context. No refresh, network or execution."),
			mcp.WithString("dir", mcp.Description("Existing child working directory; independent of the target")),
			mcp.WithString("targetDir", mcp.Description("Optional project locator; must equal the authenticated context root")),
			mcp.WithString("projectContext", mcp.Description("Authenticated installed context key; default is the registration key")),
			mcp.WithBoolean("offline", mcp.DefaultBool(true), mcp.Description("Only offline=true is supported")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
			outputSchema(entry.op),
		), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a readonlyVerifyArgs) (*mcp.CallToolResult, error) {
			cwd, failure := s.workDir(entry.op, "dir", a.Dir)
			if failure != nil {
				return failure, nil
			}
			argv := append([]string(nil), entry.argv...)
			if a.TargetDir != "" {
				argv = append(argv, "--dir", a.TargetDir)
			}
			if a.ProjectContext != "" {
				argv = append(argv, "--project-context", a.ProjectContext)
			}
			offline := "--offline=true"
			if a.Offline != nil && !*a.Offline {
				offline = "--offline=false"
			}
			argv = append(argv, offline)
			return s.callStructured(ctx, entry.op, cwd, argv, shortCall), nil
		}))
	}
}
