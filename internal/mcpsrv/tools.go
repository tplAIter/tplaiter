package mcpsrv

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// All tool and parameter descriptions are IN RUSSIAN: AI agents, the intended
// users of this server, read them. Schemas are typed (mcp.NewTypedToolHandler
// binds JSON arguments to a structure).
//
// Deliberately NOT exposed (see the decisions in docs and the final report):
//   - auth_* / repo add with a token: passing secrets through an agent is a bad
//     idea; a human sets tokens up in advance (`tplaiter repo add` with
//     interactive auth or --token-stdin). The MCP server does not connect stdin
//     to children.
//   - upgrade / self-upgrade: an agent performing git push/MR work or binary
//     self-upgrade without explicit human approval is dangerous.

// toolRegistrars lists every tool domain in registration order. Each domain
// lives in its own tools_<domain>.go file as a (s *Server) add<Domain>Tools
// method. A work package that adds a domain adds its file plus ONE line here;
// merge conflicts on this list are resolved by union.
//
// The registered tool names are pinned by testdata/tools.golden.txt
// (TestToolRegistryGolden); update the golden together with this list.
var toolRegistrars = []func(*Server){
	(*Server).addTrustTools,
	(*Server).addRepoTools,
	(*Server).addTemplateTools,
	(*Server).addProjectTools,
	(*Server).addSettingsTools,
	(*Server).addGenTools,
	(*Server).addWorkspaceTools,
	(*Server).addTemplateAuthorTools,
	(*Server).addMiscTools,
}

// registerTools registers every tool domain listed in toolRegistrars.
func (s *Server) registerTools() {
	for _, register := range toolRegistrars {
		register(s)
	}
}

// exec is the common tool execution path: it starts a child process and
// returns a fixed failure code without exposing child diagnostics.
func (s *Server) exec(ctx context.Context, cwd string, argv []string, timeout time.Duration) *mcp.CallToolResult {
	res, runErr := s.runCLI(ctx, cwd, argv, timeout)
	return toolResult(res, runErr)
}
