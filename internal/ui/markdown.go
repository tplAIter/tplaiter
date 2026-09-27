package ui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/glamour"
)

// markdownWordWrap is the wrap width for Glamour markdown rendering. It matches
// a typical terminal width and is not tied to the actual width, which Glamour
// cannot determine without a TTY.
const markdownWordWrap = 100

// Markdown writes src markdown to w. When colorEnabled (TTY and no NO_COLOR;
// see [ColorEnabled]), it renders through Glamour with automatic styling, which
// determines the light or dark terminal background. Otherwise it writes source
// text unchanged so pipes and CI receive clean Markdown without ANSI codes or
// distorted markup.
func Markdown(w io.Writer, src []byte, colorEnabled bool) error {
	if !colorEnabled {
		if _, err := w.Write(src); err != nil {
			return fmt.Errorf("ui: запись markdown: %w", err)
		}
		if len(src) == 0 || src[len(src)-1] != '\n' {
			fmt.Fprintln(w)
		}
		return nil
	}

	r, err := glamour.NewTermRenderer(glamour.WithAutoStyle(), glamour.WithWordWrap(markdownWordWrap))
	if err != nil {
		return fmt.Errorf("ui: инициализация markdown-рендера: %w", err)
	}
	out, err := r.Render(string(src))
	if err != nil {
		return fmt.Errorf("ui: рендер markdown: %w", err)
	}
	fmt.Fprint(w, out)
	return nil
}
