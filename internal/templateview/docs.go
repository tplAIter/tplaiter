package templateview

import (
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/ui"
)

// RenderDocs writes the template documentation file (metadata.docs) to w through
// [ui.Markdown]: Glamour renders it when color is enabled; otherwise it is written
// unchanged without ANSI codes.
func RenderDocs(w io.Writer, raw []byte, colorEnabled bool) error {
	if err := ui.Markdown(w, raw, colorEnabled); err != nil {
		return fmt.Errorf("templateview: docs: %w", err)
	}
	return nil
}
