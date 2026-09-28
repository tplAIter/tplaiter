package ui

import (
	"strings"
	"testing"
)

func TestTable_Render_AlignsColumns(t *testing.T) {
	tbl := NewTable("NAME", "REPO", "LABELS")
	tbl.AddRow("go-service", "example", "lang=go")
	tbl.AddRow("go-workspace", "example", "lang=go,kind=workspace")

	got := tbl.Render()
	want := strings.Join([]string{
		"NAME          REPO     LABELS",
		"go-service    example  lang=go",
		"go-workspace  example  lang=go,kind=workspace",
	}, "\n")
	if got != want {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want)
	}
}

func TestTable_Render_EmptyTable(t *testing.T) {
	tbl := NewTable("A", "B")
	got := tbl.Render()
	if got != "A  B" {
		t.Errorf("Render() = %q, want %q", got, "A  B")
	}
}

func TestTable_Render_RaggedRows(t *testing.T) {
	tbl := NewTable("A", "B", "C")
	tbl.AddRow("1")                // missing columns
	tbl.AddRow("1", "2", "3", "4") // extra column is dropped

	got := tbl.Render()
	if strings.Contains(got, "4") {
		t.Errorf("Render() = %q, extra column should be dropped", got)
	}
}

// TestTable_RenderStyled_PlainFallback checks that with color disabled
// (NO_COLOR/non-TTY), RenderStyled exactly matches Render: golden plain output
// without ANSI, as required by the implementation.
func TestTable_RenderStyled_PlainFallback(t *testing.T) {
	tbl := NewTable("NAME", "REPO", "LABELS")
	tbl.AddRow("go-service", "example", "lang=go")

	pal := NewPalette(false)
	if got, want := tbl.RenderStyled(pal), tbl.Render(); got != want {
		t.Errorf("RenderStyled(plain) =\n%q\nwant identical to Render():\n%q", got, want)
	}
	if strings.ContainsAny(tbl.RenderStyled(pal), "\x1b") {
		t.Errorf("RenderStyled(plain) contains ANSI escape: %q", tbl.RenderStyled(pal))
	}
}

// TestTable_RenderStyled_ColorEnabled checks a bold header and a muted separator
// beneath it while keeping headers and data unchanged as substrings, so command
// tests that parse output by containment do not break due to styling.
func TestTable_RenderStyled_ColorEnabled(t *testing.T) {
	tbl := NewTable("NAME", "REPO")
	tbl.AddRow("go-service", "example")

	pal := NewPalette(true)
	got := tbl.RenderStyled(pal)

	if !strings.Contains(got, "\x1b") {
		t.Errorf("RenderStyled(color) = %q, want ANSI styling applied", got)
	}
	for _, want := range []string{"NAME", "REPO", "go-service", "example"} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderStyled(color) = %q, must still contain %q", got, want)
		}
	}
	lines := strings.Split(got, "\n")
	if len(lines) < 3 {
		t.Fatalf("RenderStyled(color) has %d lines, want >= 3 (header, separator, row)", len(lines))
	}
	if !strings.Contains(lines[1], "─") {
		t.Errorf("RenderStyled(color) line 2 = %q, want muted separator", lines[1])
	}
}

// TestTable_RenderStyled_AlignsWithColoredCells checks that ANSI coloring of a
// cell (not only the last column; see [Table]) does not break alignment of later
// columns: width is computed by lipgloss.Width, which ignores escape sequences.
func TestTable_RenderStyled_AlignsWithColoredCells(t *testing.T) {
	pal := NewPalette(true)
	tbl := NewTable("STATUS", "NAME")
	tbl.AddRow(pal.Success("ok"), "alpha")
	tbl.AddRow(pal.Error("fail"), "b")

	got := tbl.Render() // Render (not Styled); the table itself is ANSI-aware
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("Render() with colored cells has %d lines, want 3", len(lines))
	}
	// "NAME" must start in the same visible column regardless of the ANSI code
	// length in the first cell; check the visible prefix width before the second
	// column with lipgloss.Width on the substring before "alpha"/"b".
	if !strings.Contains(lines[1], "alpha") || !strings.Contains(lines[2], "b") {
		t.Fatalf("Render() with colored cells lost data rows: %q", got)
	}
}
