package ui

import (
	"fmt"
	"io"
)

// Section prints a report section title (doctor sections, update --all, stats)
// in bold (see [Palette.Header]), using the shared CLI section-heading style.
func Section(w io.Writer, pal Palette, title string) {
	fmt.Fprintln(w, pal.Header(title))
}
