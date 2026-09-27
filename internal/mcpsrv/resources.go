package mcpsrv

import (
	"context"
	"fmt"
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
//	                          directory dir (a path-parameterized resource template).
func (s *Server) registerResources() {
	s.mcp.AddResource(
		mcp.NewResource(
			"tplaiter://config", "Конфигурация tplaiter",
			mcp.WithResourceDescription("Список добавленных репозиториев шаблонов без секретов (токены не раскрываются)."),
			mcp.WithMIMEType("text/plain"),
		),
		s.readConfigResource,
	)

	s.mcp.AddResourceTemplate(
		mcp.NewResourceTemplate(
			"tplaiter://project/{dir}", "Манифест проекта tplaiter",
			mcp.WithTemplateDescription("Содержимое .tplaiter/project.yaml проекта по абсолютному пути dir."),
			mcp.WithTemplateMIMEType("application/yaml"),
		),
		s.readProjectResource,
	)
}

// readConfigResource returns `repo list` as text. By construction this output
// contains no tokens (ALIAS/URL/TYPE/TEMPLATES/UPDATED), so it is safe for an agent.
func (s *Server) readConfigResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	res, runErr := s.runCLI(ctx, "", argvRepoList(), defaultTimeout)
	if failed(res, runErr) {
		return nil, fmt.Errorf("tplaiter://config: %s", formatFailure(res, runErr))
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
		return nil, fmt.Errorf("tplaiter://project: не указан каталог проекта в URI %q", req.Params.URI)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("tplaiter://project: некорректный путь %q: %w", dir, err)
	}

	marker := filepath.Join(abs, project.MarkerRelPath)
	data, err := os.ReadFile(marker)
	if err != nil {
		return nil, fmt.Errorf("tplaiter://project: чтение %s: %w", marker, err)
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/yaml", Text: string(data)},
	}, nil
}
