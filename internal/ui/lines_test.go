package ui

import (
	"strings"
	"testing"
)

func TestLineHelpers_PlainFallback(t *testing.T) {
	pal := NewPalette(false)
	cases := []struct {
		name string
		fn   func(Palette, string) string
		want string
	}{
		{"SuccessLine", SuccessLine, "✓ ok"},
		{"WarnLine", WarnLine, "! ok"},
		{"ErrorLine", ErrorLine, "✗ ok"},
		{"InfoLine", InfoLine, "ℹ ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fn(pal, "ok"); got != c.want {
				t.Errorf("%s(plain, %q) = %q, want %q", c.name, "ok", got, c.want)
			}
		})
	}
}

func TestLineHelpers_ColorEnabledKeepsMessage(t *testing.T) {
	pal := NewPalette(true)
	cases := []struct {
		name string
		fn   func(Palette, string) string
	}{
		{"SuccessLine", SuccessLine},
		{"WarnLine", WarnLine},
		{"ErrorLine", ErrorLine},
		{"InfoLine", InfoLine},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.fn(pal, "ok")
			if !strings.Contains(got, "ok") {
				t.Errorf("%s(color, %q) = %q, must still contain the message", c.name, "ok", got)
			}
		})
	}
}

func TestErrorPrefix(t *testing.T) {
	if got := ErrorPrefix(NewPalette(false)); got != "error:" {
		t.Errorf("ErrorPrefix(plain) = %q, want %q", got, "error:")
	}
	if got := ErrorPrefix(NewPalette(true)); !strings.Contains(got, "error:") {
		t.Errorf("ErrorPrefix(color) = %q, must still contain %q", got, "error:")
	}
}
