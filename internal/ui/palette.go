// Package ui — общие UI-примитивы CLI tplater: цветовая палитра и
// табличный вывод. Полноценная полировка (glamour/bubbles, интерактивные
// компоненты) — реализация реализацию; здесь только заготовка, на которую она
// опирается.
package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Цвета палитры (ANSI256, безопасны в большинстве терминалов).
const (
	colorSuccess = lipgloss.Color("42")  // зелёный
	colorWarn    = lipgloss.Color("214") // оранжевый
	colorError   = lipgloss.Color("203") // красный
	colorMuted   = lipgloss.Color("246") // серый
)

// Palette — набор семантических стилей вывода. Zero-value эквивалентен
// NewPalette(false) (без цвета) — на всякий случай, если где-то забудут
// вызвать конструктор.
type Palette struct {
	enabled bool
	success lipgloss.Style
	warn    lipgloss.Style
	errorSt lipgloss.Style
	muted   lipgloss.Style
	header  lipgloss.Style
}

// NewPalette создаёт палитру с явно заданным флагом цвета. Используйте
// [Default], чтобы определить флаг автоматически по NO_COLOR/TTY.
//
// lipgloss по умолчанию сам определяет цветовой профиль по TTY-детекту, что
// не подходит нам: мы хотим управлять этим явно (тестируемо) через
// [ColorEnabled], а не полагаться на автодетект внутри lipgloss (который,
// например, всегда отключает цвет в `go test`, где stdout не TTY). Поэтому
// стили строятся на отдельном рендерере с принудительно заданным профилем.
func NewPalette(colorEnabled bool) Palette {
	profile := termenv.Ascii
	if colorEnabled {
		profile = termenv.ANSI256
	}
	r := lipgloss.NewRenderer(os.Stdout)
	r.SetColorProfile(profile)

	return Palette{
		enabled: colorEnabled,
		success: r.NewStyle().Foreground(colorSuccess),
		warn:    r.NewStyle().Foreground(colorWarn),
		errorSt: r.NewStyle().Foreground(colorError),
		muted:   r.NewStyle().Foreground(colorMuted),
		header:  r.NewStyle().Bold(true),
	}
}

// Default возвращает палитру для текущего окружения процесса
// (см. [ColorEnabled]).
func Default() Palette {
	return NewPalette(ColorEnabled())
}

// Enabled сообщает, включён ли цвет в этой палитре.
func (p Palette) Enabled() bool { return p.enabled }

// Success раскрашивает s в цвет успеха либо возвращает s как есть (plain-фоллбек).
func (p Palette) Success(s string) string { return p.render(p.success, s) }

// Warn раскрашивает s в цвет предупреждения либо возвращает s как есть.
func (p Palette) Warn(s string) string { return p.render(p.warn, s) }

// Error раскрашивает s в цвет ошибки либо возвращает s как есть.
func (p Palette) Error(s string) string { return p.render(p.errorSt, s) }

// Muted приглушает s (вспомогательный/второстепенный текст) либо возвращает
// s как есть.
func (p Palette) Muted(s string) string { return p.render(p.muted, s) }

// Header выделяет s жирным (заголовки секций отчётов, заголовки таблиц —
// см. [Table.RenderStyled] и [Section]) либо возвращает s как есть.
func (p Palette) Header(s string) string { return p.render(p.header, s) }

func (p Palette) render(st lipgloss.Style, s string) string {
	if !p.enabled {
		return s
	}
	return st.Render(s)
}
