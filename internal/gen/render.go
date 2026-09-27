package gen

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/engine"
)

// renderTemplateFile читает и рендерит файл-сниппет path (сниппет либо
// вставка якоря) через text/template с полным [engine.FuncMap] (не только
// [engine.StaticFuncMap] — сниппетам доступны и `is`/`has`, дополнительно к
// case-хелперам, без обратной несовместимости: FuncMap строго расширяет
// StaticFuncMap).
func renderTemplateFile(path string, data Context) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение сниппета %s: %w", path, err)
	}
	tmpl, err := template.New(filepath.Base(path)).Funcs(engine.FuncMap(data.Settings)).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("разбор сниппета %s: %w", path, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("рендер сниппета %s: %w", path, err)
	}
	return buf.Bytes(), nil
}

// renderTargetPath рендерит шаблон целевого пути генератора (Generator.Target,
// : `"internal/usecase/{{ .Name.Snake }}.go"`).
func renderTargetPath(pattern string, data Context) (string, error) {
	tmpl, err := template.New("target").Funcs(engine.FuncMap(data.Settings)).Parse(pattern)
	if err != nil {
		return "", fmt.Errorf("разбор target %q: %w", pattern, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("рендер target %q: %w", pattern, err)
	}
	return buf.String(), nil
}
