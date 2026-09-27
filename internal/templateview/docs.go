package templateview

import (
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/ui"
)

// RenderDocs печатает содержимое docs-файла шаблона (metadata.docs,
// ) в w через [ui.Markdown] (glamour при colorEnabled — :
// "glamour — рендер markdown в template show"; иначе — как есть, без ANSI).
func RenderDocs(w io.Writer, raw []byte, colorEnabled bool) error {
	if err := ui.Markdown(w, raw, colorEnabled); err != nil {
		return fmt.Errorf("templateview: docs: %w", err)
	}
	return nil
}
