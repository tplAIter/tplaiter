package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Table — monospace table output: columns align to their longest value. Column
// width uses [lipgloss.Width] (rather than len([]rune(...))), so cells already
// containing ANSI styling (see cmd/*, stats, update status columns) align
// correctly in ANY column, not only the last.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable creates a table with the given column headers.
func NewTable(headers ...string) *Table {
	return &Table{Headers: headers}
}

// AddRow adds a data row. The column count may differ from the headers: missing
// cells render empty and extras are discarded.
func (t *Table) AddRow(cols ...string) {
	t.Rows = append(t.Rows, cols)
}

// Render returns a printable table without a trailing "\n" after the last row.
// It does not style the header or add a separator; see [Table.RenderStyled] for
// that. Used as the plain fallback when color is disabled (NO_COLOR/non-TTY, see [ColorEnabled]).
func (t *Table) Render() string {
	widths := t.columnWidths()

	var b strings.Builder
	writeRow(&b, t.Headers, widths)
	for _, row := range t.Rows {
		writeRow(&b, row, widths)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// RenderStyled returns a table with a bold header and muted separator beneath
// it (the common CLI table style). When pal.Enabled() == false, the result is
// identical to [Table.Render], a safe fallback for NO_COLOR/non-TTY/CI where
// scripts parse output.
func (t *Table) RenderStyled(pal Palette) string {
	if !pal.Enabled() {
		return t.Render()
	}

	widths := t.columnWidths()

	var headerLine strings.Builder
	writeRow(&headerLine, t.Headers, widths)

	var b strings.Builder
	b.WriteString(pal.Header(strings.TrimSuffix(headerLine.String(), "\n")))
	b.WriteString("\n")
	b.WriteString(pal.Muted(separatorLine(widths)))
	b.WriteString("\n")
	for _, row := range t.Rows {
		writeRow(&b, row, widths)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// separatorLine builds a "────  ────  ..." separator with the same column widths
// as table rows (two spaces between columns; see writeRow).
func separatorLine(widths []int) string {
	parts := make([]string, len(widths))
	for i, w := range widths {
		parts[i] = strings.Repeat("─", w)
	}
	return strings.Join(parts, "  ")
}

func (t *Table) columnWidths() []int {
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i >= len(widths) {
				continue
			}
			if n := lipgloss.Width(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	return widths
}

func writeRow(b *strings.Builder, cols []string, widths []int) {
	last := len(widths) - 1
	for i, w := range widths {
		cell := ""
		if i < len(cols) {
			cell = cols[i]
		}
		b.WriteString(cell)
		if i == last {
			// Do not pad the last column, avoiding trailing whitespace on every row.
			continue
		}
		if pad := w - lipgloss.Width(cell); pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteString("  ")
	}
	b.WriteString("\n")
}
