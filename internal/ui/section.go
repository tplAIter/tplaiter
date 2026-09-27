package ui

import (
	"fmt"
	"io"
)

// Section печатает заголовок раздела отчёта (doctor-секции, update --all,
// stats) жирным (см. [Palette.Header]) — единый вид заголовков разделов CLI
// (реализация реализацию, требование консистентности).
func Section(w io.Writer, pal Palette, title string) {
	fmt.Fprintln(w, pal.Header(title))
}
