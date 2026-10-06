// Package mcpsrv implements the tplaiter MCP server: it exposes CLI commands as
// MCP tools for AI agents (derivation 6 in docs/research/clean-codegen.md §1,
// “MCP server over CLI”). Its architecture follows the goca subprocess pattern:
// each tool executes the same tplaiter binary in a separate process with separate
// arguments (without shell interpolation), rather than invoking Cobra commands
// in process. In-process calls are unsafe because global Cobra flag state leaks
// between tool calls; a process per call provides complete isolation.
//
// The transport is stdio JSON-RPC (server.ServeStdio). Server logs go to stderr:
// stdout is occupied by the protocol.
package mcpsrv

import (
	"bufio"
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/mark3labs/mcp-go/server"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Server wraps *server.MCPServer with the tplaiter binary path and a child-process
// runner, mockable in tests through execx.RecordingRunner.
type Server struct {
	exe        string
	version    string
	runner     execx.Runner
	mcp        *server.MCPServer
	installed  bool
	direct     bool
	limits     Limits
	stage      *heldStage
	childEnv   []string
	mu         sync.Mutex
	closed     bool
	closeDone  chan struct{}
	closeErr   error
	children   sync.WaitGroup
	rootFrames *rootFrames
	graph      *graphTransport
	batch      *batchTransport
}

// New constructs the tplaiter MCP server and registers all tools and resources.
//
//	exe     — absolute path to the tplaiter binary (usually os.Executable());
//	          every tool executes it as its child process;
//	version — tplaiter version (for Implementation in initialize);
//	runner  — child-process runner (execx.Exec{} in production and
//	          execx.RecordingRunner in tests).
func New(exe, version string, runner execx.Runner) *Server {
	m := server.NewMCPServer(
		"tplaiter",
		version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
		server.WithRecovery(),
		// Every tool declares a result/v1 outputSchema; the server refuses to
		// return structured content that violates it.
		server.WithOutputSchemaValidation(),
	)
	if version == "" {
		version = "dev"
	}
	s := &Server{exe: exe, version: version, runner: runner, mcp: m, limits: DefaultLimits(), closeDone: make(chan struct{})}
	s.registerTools()
	s.registerResources()
	s.rootFrames = s.installRootFrames()
	s.installGraphHooks()
	s.installBatchHooks()
	return s
}

// NewInstalled constructs the production transport after the caller has
// authenticated the installed registration and closed its startup runtime.
// The executable path is fixed here and cannot be supplied by an MCP tool.
func NewInstalled(exe, version, scratchRoot string) *Server {
	stage, err := newHeldStage(exe, scratchRoot)
	if err != nil {
		return nil
	}
	s := New(exe, version, nil)
	s.installed = true
	s.stage = stage
	s.childEnv = capturedChildEnvironment()
	return s
}

var errTransportUnavailable = errors.New("MCP_UNAVAILABLE")

// MCP returns the underlying *server.MCPServer, which tests need to connect an
// in-process client (client.NewInProcessClient).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// ServeStdio runs the server over stdio JSON-RPC. Protocol errors are logged to
// stderr because stdout belongs to the protocol. It blocks until termination
// (stdin EOF or SIGINT/SIGTERM, handled inside ServeStdio).
func (s *Server) ServeStdio() error {
	errLog := log.New(os.Stderr, "tplaiter-mcp ", log.LstdFlags)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	output, closeOutput, err := rootStdioOutput()
	if err != nil {
		_ = s.Close()
		return errTransportUnavailable
	}
	defer closeOutput()
	rootWriter := &rootResponseWriter{frames: s.rootFrames, server: s, out: output}
	graph := newGraphTransport(ctx, s, &rootCancellationReader{in: os.Stdin, frames: s.rootFrames}, rootWriter, output)
	graph.input = bufio.NewReader(&semanticInput{input: graph.input, graph: graph})
	graph.input = bufio.NewReader(&discoveryInput{input: graph.input, graph: graph})
	graph.stopStdio = cancel
	s.mu.Lock()
	s.graph = graph
	s.mu.Unlock()
	defer graph.close()
	batch := newBatchTransport(ctx, s, graph)
	s.mu.Lock()
	s.batch = batch
	s.mu.Unlock()
	defer batch.close()
	stdio := server.NewStdioServer(s.mcp)
	stdio.SetContextFunc(batch.bindSession)
	stdio.SetErrorLogger(errLog)
	serveErr := stdio.Listen(ctx, batch, batch)
	s.rootFrames.close()
	closeErr := s.Close()
	if serveErr != nil || closeErr != nil {
		return errTransportUnavailable
	}
	return nil
}

// Close releases the verified staged image after all active children have
// been reaped by runCLI. It is safe to call more than once.
func (s *Server) Close() error {
	if s == nil || (s.stage == nil && !s.direct) {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return s.closeErr
	}
	s.closed = true
	graph := s.graph
	batch := s.batch
	s.mu.Unlock()
	if batch != nil {
		batch.close()
	}
	if graph != nil {
		graph.close()
	}
	s.rootFrames.close()
	s.children.Wait()
	var err error
	if s.stage != nil {
		err = s.stage.Close()
	}
	if err != nil {
		err = errTransportUnavailable
	}
	s.mu.Lock()
	s.closeErr = err
	close(s.closeDone)
	s.mu.Unlock()
	return err
}

// NewDirect constructs a server whose tools execute exe directly, without
// the installed held-stage image. Children still run with the fixed,
// sanitized environment, in their own process group, with bounded output.
// It exists for the stdio contract harness and tests; the production
// `tplaiter mcp-server` always uses [NewInstalled].
func NewDirect(exe, version string) *Server {
	if !filepath.IsAbs(exe) {
		return nil
	}
	s := New(exe, version, nil)
	s.direct = true
	s.childEnv = capturedChildEnvironment()
	return s
}
