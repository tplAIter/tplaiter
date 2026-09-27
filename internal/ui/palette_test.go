package ui

import (
	"strings"
	"testing"
)

func TestPalette_PlainFallback(t *testing.T) {
	p := NewPalette(false)
	if p.Enabled() {
		t.Fatal("NewPalette(false).Enabled() = true")
	}
	for _, tc := range []struct {
		name string
		fn   func(string) string
	}{
		{"Success", p.Success},
		{"Warn", p.Warn},
		{"Error", p.Error},
		{"Muted", p.Muted},
	} {
		if got := tc.fn("text"); got != "text" {
			t.Errorf("%s(%q) = %q, want unmodified plain text", tc.name, "text", got)
		}
	}
}

func TestPalette_ColorEnabledAddsEscapes(t *testing.T) {
	p := NewPalette(true)
	if !p.Enabled() {
		t.Fatal("NewPalette(true).Enabled() = false")
	}
	for _, tc := range []struct {
		name string
		fn   func(string) string
	}{
		{"Success", p.Success},
		{"Warn", p.Warn},
		{"Error", p.Error},
		{"Muted", p.Muted},
	} {
		got := tc.fn("text")
		if !strings.Contains(got, "text") {
			t.Errorf("%s(%q) = %q, must still contain the original text", tc.name, "text", got)
		}
		if got == "text" {
			t.Errorf("%s(%q) = %q, expected ANSI styling to be applied when color is enabled", tc.name, "text", got)
		}
	}
}

func TestDefault_MatchesColorEnabled(t *testing.T) {
	p := Default()
	if p.Enabled() != ColorEnabled() {
		t.Errorf("Default().Enabled() = %v, want ColorEnabled() = %v", p.Enabled(), ColorEnabled())
	}
}
