package ui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/glamour"
)

// markdownWordWrap — ширина переноса строк markdown-рендера glamour;
// совпадает с типичной шириной терминала, не привязана к реальной (glamour
// сам её не определяет без TTY).
const markdownWordWrap = 100

// Markdown печатает markdown-текст src в w. При colorEnabled (TTY и нет
// NO_COLOR — см. [ColorEnabled]) рендерится через glamour с авто-стилем
// (сам определяет светлый/тёмный фон терминала); иначе печатается исходный
// текст как есть — именно так, а не "выключенным" glamour-рендером, чтобы
// пайпы/CI получали чистый markdown без ANSI и без искажений разметки.
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
