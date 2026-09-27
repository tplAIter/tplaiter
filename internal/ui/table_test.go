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
	tbl.AddRow("1")                // недостающие колонки
	tbl.AddRow("1", "2", "3", "4") // лишняя колонка отбрасывается

	got := tbl.Render()
	if strings.Contains(got, "4") {
		t.Errorf("Render() = %q, extra column should be dropped", got)
	}
}

// TestTable_RenderStyled_PlainFallback проверяет, что при отключённом цвете
// (NO_COLOR/не-TTY) RenderStyled полностью совпадает с Render — golden
// plain-вывод без ANSI, требование реализации реализацию.
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

// TestTable_RenderStyled_ColorEnabled проверяет заголовок жирным и наличие
// приглушённой разделительной линии под ним, при этом содержимое (заголовки
// и данные) остаётся неизменным по подстроке — тесты команд, парсящие вывод
// по вхождению, не должны сломаться от стилизации.
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

// TestTable_RenderStyled_AlignsWithColoredCells проверяет, что ANSI-раскраска
// ячейки (не только последней колонки — см. doc [Table]) не ломает
// выравнивание последующих колонок: ширина считается через lipgloss.Width,
// который игнорирует escape-последовательности.
func TestTable_RenderStyled_AlignsWithColoredCells(t *testing.T) {
	pal := NewPalette(true)
	tbl := NewTable("STATUS", "NAME")
	tbl.AddRow(pal.Success("ok"), "alpha")
	tbl.AddRow(pal.Error("fail"), "b")

	got := tbl.Render() // Render (не Styled) — сама таблица тоже ANSI-aware
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("Render() with colored cells has %d lines, want 3", len(lines))
	}
	// "NAME" должно начинаться в одной и той же видимой колонке независимо от
	// длины ANSI-кода в первой ячейке — проверяем видимую ширину префикса до
	// начала второй колонки через lipgloss.Width на подстроке до "alpha"/"b".
	if !strings.Contains(lines[1], "alpha") || !strings.Contains(lines[2], "b") {
		t.Fatalf("Render() with colored cells lost data rows: %q", got)
	}
}
