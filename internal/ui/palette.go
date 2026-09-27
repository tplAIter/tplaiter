// Package ui provides shared UI primitives for the tplater CLI: color palette
// and table output. Rich polish (Glamour/Bubbles and interactive components)
// builds on this foundation.
package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Palette colors (ANSI256, safe in most terminals).
const (
	colorSuccess = lipgloss.Color("42")  // green
	colorWarn    = lipgloss.Color("214") // orange
	colorError   = lipgloss.Color("203") // red
	colorMuted   = lipgloss.Color("246") // gray
)

// Palette is a set of semantic output styles. Its zero value is equivalent to
// NewPalette(false), providing a safe fallback when a caller misses the constructor.
type Palette struct {
	enabled bool
	success lipgloss.Style
	warn    lipgloss.Style
	errorSt lipgloss.Style
	muted   lipgloss.Style
	header  lipgloss.Style
}

// NewPalette creates a palette with an explicit color flag. Use [Default] to
// detect the flag from NO_COLOR/TTY automatically.
//
// Lipgloss normally detects its color profile from TTY detection. We need
// explicit, testable control through [ColorEnabled], rather than its autodetect
// behavior, which disables color in `go test` because stdout is not a TTY.
// Styles therefore use a separate renderer with a forced profile.
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

// Default returns a palette for the current process environment (see [ColorEnabled]).
func Default() Palette {
	return NewPalette(ColorEnabled())
}

// Enabled reports whether color is enabled in this palette.
func (p Palette) Enabled() bool { return p.enabled }

// Success colors s as success or returns s unchanged as a plain fallback.
func (p Palette) Success(s string) string { return p.render(p.success, s) }

// Warn colors s as a warning or returns s unchanged.
func (p Palette) Warn(s string) string { return p.render(p.warn, s) }

// Error colors s as an error or returns s unchanged.
func (p Palette) Error(s string) string { return p.render(p.errorSt, s) }

// Muted mutes auxiliary/secondary text s or returns it unchanged.
func (p Palette) Muted(s string) string { return p.render(p.muted, s) }

// Header makes s bold for report-section and table headings (see
// [Table.RenderStyled] and [Section]) or returns it unchanged.
func (p Palette) Header(s string) string { return p.render(p.header, s) }

func (p Palette) render(st lipgloss.Style, s string) string {
	if !p.enabled {
		return s
	}
	return st.Render(s)
}
