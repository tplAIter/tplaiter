package mcpsrv

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/project"
)

// registerResources exposes two resources:
//
//	tplaiter://config        — a redacted configuration: repository list WITHOUT
//	                          tokens (`repo list` output; tokens are stored
//	                          separately in the keyring and never appear here).
//	tplaiter://project/{dir} — the .tplaiter/project.yaml content for project
//	                          directory dir, the percent-encoded absolute path
//	                          ("/" as %2F; a path-parameterized resource template).
func (s *Server) registerResources() {
	s.mcp.AddResource(
		mcp.NewResource(
			"tplaiter://config", "tplaiter configuration",
			mcp.WithResourceDescription("List of added template repositories without secrets (tokens are not exposed)."),
			mcp.WithMIMEType("text/plain"),
		),
		s.readConfigResource,
	)

	s.mcp.AddResourceTemplate(
		mcp.NewResourceTemplate(
			"tplaiter://project/{dir}", "tplaiter project manifest",
			mcp.WithTemplateDescription("Contents of .tplaiter/project.yaml for the project at absolute path dir, percent-encoded as one URI segment (\"/\" as %2F)."),
			mcp.WithTemplateMIMEType("application/yaml"),
		),
		s.readProjectResource,
	)
}

// readConfigResource returns `repo list` as text. By construction this output
// contains no tokens (ALIAS/URL/TYPE/TEMPLATES/UPDATED), so it is safe for an agent.
func (s *Server) readConfigResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	res, runErr := s.runCLI(ctx, "", argvRepoList(), s.timeout(shortCall))
	if failed(res, runErr) {
		code := transportCode(res, runErr)
		if code == "" {
			code = "MCP_CLI_FAILED"
		}
		return nil, fmt.Errorf("tplaiter://config: %s", code)
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "text/plain", Text: res.Stdout},
	}, nil
}

// readProjectResource reads .tplaiter/project.yaml from the directory extracted
// from tplaiter://project/{dir}. dir is made absolute; the server does not read
// outside the filesystem (only the local project marker file).
func (s *Server) readProjectResource(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	dir := strings.TrimPrefix(req.Params.URI, "tplaiter://project/")
	if dir == "" || dir == req.Params.URI {
		return nil, fmt.Errorf("tplaiter://project: project directory not specified in URI %q", req.Params.URI)
	}
	// {dir} is one URI segment, so an absolute path arrives percent-encoded.
	decoded, err := url.PathUnescape(dir)
	if err != nil {
		return nil, fmt.Errorf("tplaiter://project: invalid percent-encoding in URI %q", req.Params.URI)
	}
	dir = decoded
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("tplaiter://project: invalid path %q: %w", dir, err)
	}

	marker := filepath.Join(abs, project.MarkerRelPath)
	data, err := os.ReadFile(marker)
	if err != nil {
		return nil, fmt.Errorf("tplaiter://project: reading %s: %w", marker, err)
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/yaml", Text: string(data)},
	}, nil
}
