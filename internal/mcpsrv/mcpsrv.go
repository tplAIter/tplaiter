// Package mcpsrv implements the tplater MCP server: it exposes CLI commands as
// MCP tools for AI agents (derivation 6 in docs/research/clean-codegen.md §1,
// “MCP server over CLI”). Its architecture follows the goca subprocess pattern:
// each tool executes the same tplater binary in a separate process with separate
// arguments (without shell interpolation), rather than invoking Cobra commands
// in process. In-process calls are unsafe because global Cobra flag state leaks
// between tool calls; a process per call provides complete isolation.
//
// The transport is stdio JSON-RPC (server.ServeStdio). Server logs go to stderr:
// stdout is occupied by the protocol.
package mcpsrv

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Server wraps *server.MCPServer with the tplater binary path and a child-process
// runner, mockable in tests through execx.RecordingRunner.
type Server struct {
	exe    string
	runner execx.Runner
	mcp    *server.MCPServer
}

// New constructs the tplater MCP server and registers all tools and resources.
//
//	exe     — absolute path to the tplater binary (usually os.Executable());
//	          every tool executes it as its child process;
//	version — tplater version (for Implementation in initialize);
//	runner  — child-process runner (execx.Exec{} in production and
//	          execx.RecordingRunner in tests).
func New(exe, version string, runner execx.Runner) *Server {
	m := server.NewMCPServer(
		"tplaiter",
		version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
		server.WithRecovery(),
	)
	s := &Server{exe: exe, runner: runner, mcp: m}
	s.registerTools()
	s.registerResources()
	return s
}

// MCP returns the underlying *server.MCPServer, which tests need to connect an
// in-process client (client.NewInProcessClient).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// ServeStdio runs the server over stdio JSON-RPC. Protocol errors are logged to
// stderr because stdout belongs to the protocol. It blocks until termination
// (stdin EOF or SIGINT/SIGTERM, handled inside ServeStdio).
func (s *Server) ServeStdio() error {
	errLog := log.New(os.Stderr, "tplaiter-mcp ", log.LstdFlags)
	return server.ServeStdio(s.mcp, server.WithErrorLogger(errLog))
}
