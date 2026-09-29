package gen

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/engine"
)

// renderTemplateFile reads and renders snippet path (snippet or anchor
// insertion) through text/template with the full [engine.FuncMap] (not only
// [engine.StaticFuncMap]; snippets also get `is`/`has` in addition to case
// helpers, without backward incompatibility because FuncMap is a strict superset).
// StaticFuncMap).
func renderTemplateFile(path string, data Context) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snippet %s: %w", path, err)
	}
	tmpl, err := template.New(filepath.Base(path)).Funcs(engine.FuncMap(data.Settings)).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing snippet %s: %w", path, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("rendering snippet %s: %w", path, err)
	}
	return buf.Bytes(), nil
}

// renderTargetPath renders the generator target-path template (Generator.Target,
// : `"internal/usecase/{{ .Name.Snake }}.go"`).
func renderTargetPath(pattern string, data Context) (string, error) {
	tmpl, err := template.New("target").Funcs(engine.FuncMap(data.Settings)).Parse(pattern)
	if err != nil {
		return "", fmt.Errorf("parsing target %q: %w", pattern, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering target %q: %w", pattern, err)
	}
	return buf.String(), nil
}
