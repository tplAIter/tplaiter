package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Table — табличный вывод моноширинным текстом: колонки выравниваются по
// самому длинному значению. Ширина колонок считается через [lipgloss.Width]
// (а не len([]rune(...))), поэтому ячейки, уже содержащие ANSI-раскраску
// (см. пакеты cmd/*, stats, update — колонки статусов), выравниваются
// корректно в ЛЮБОЙ колонке, не только в последней.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable создаёт таблицу с заданными заголовками столбцов.
func NewTable(headers ...string) *Table {
	return &Table{Headers: headers}
}

// AddRow добавляет строку данных. Число колонок может не совпадать с
// заголовками — недостающие ячейки рендерятся пустыми, лишние отбрасываются.
func (t *Table) AddRow(cols ...string) {
	t.Rows = append(t.Rows, cols)
}

// Render возвращает готовую к печати таблицу, без завершающего "\n" сверх
// последней строки. Не стилизует заголовок и не добавляет разделитель — для
// этого см. [Table.RenderStyled]. Используется как plain-фоллбек при
// отключённом цвете (NO_COLOR/не-TTY, см. [ColorEnabled]).
func (t *Table) Render() string {
	widths := t.columnWidths()

	var b strings.Builder
	writeRow(&b, t.Headers, widths)
	for _, row := range t.Rows {
		writeRow(&b, row, widths)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// RenderStyled возвращает таблицу с заголовком, выделенным жирным, и
// приглушённой разделительной линией под ним (единый вид таблиц CLI, реализация
// реализацию). При pal.Enabled() == false результат идентичен [Table.Render] —
// безопасный фоллбек для NO_COLOR/не-TTY/CI, где вывод разбирается скриптами.
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

// separatorLine строит разделитель "────  ────  ..." той же ширины колонок,
// что и строки таблицы (два пробела между колонками — см. writeRow).
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
			// Последнюю колонку не дополняем пробелами — избегаем висящего
			// trailing whitespace в каждой строке.
			continue
		}
		if pad := w - lipgloss.Width(cell); pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteString("  ")
	}
	b.WriteString("\n")
}
