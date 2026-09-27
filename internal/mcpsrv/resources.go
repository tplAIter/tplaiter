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

// registerResources выставляет два ресурса:
//
//	tplaiter://config        — маскированный конфиг: список репозиториев БЕЗ
//	                          токенов (вывод `repo list`; токены хранятся
//	                          отдельно в keyring и в этот вывод не попадают).
//	tplaiter://project/{dir} — содержимое .tplaiter/project.yaml проекта по пути
//	                          dir (шаблон-ресурс с параметром пути).
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

// readConfigResource отдаёт `repo list` как текст. Этот вывод по построению не
// содержит токенов (ALIAS/URL/TYPE/TEMPLATES/UPDATED), поэтому безопасен для
// агента.
func (s *Server) readConfigResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	res, runErr := s.runCLI(ctx, "", argvRepoList(), defaultTimeout)
	if failed(res, runErr) {
		return nil, fmt.Errorf("tplaiter://config: %s", formatFailure(res, runErr))
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "text/plain", Text: res.Stdout},
	}, nil
}

// readProjectResource читает .tplaiter/project.yaml из каталога, извлечённого из
// URI tplaiter://project/{dir}. dir абсолютизируется; чтение вне ФС сервер не
// делает (только локальный файл маркера проекта).
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
