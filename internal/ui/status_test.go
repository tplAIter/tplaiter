package ui

import (
	"strings"
	"testing"
)

func TestStatusIcon_Matrix(t *testing.T) {
	cases := []struct {
		name string
		kind StatusKind
		want string
	}{
		{"OK", StatusOK, "✓"},
		{"Warn", StatusWarn, "!"},
		{"Fail", StatusFail, "✗"},
		{"Planned", StatusPlanned, "○"},
	}

	for _, enabled := range []bool{false, true} {
		pal := NewPalette(enabled)
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got := StatusIcon(pal, c.kind)
				if !strings.Contains(got, c.want) {
					t.Errorf("StatusIcon(pal(enabled=%v), %v) = %q, want to contain %q", enabled, c.kind, got, c.want)
				}
				if !enabled && got != c.want {
					t.Errorf("StatusIcon(pal(enabled=false), %v) = %q, want plain %q (no ANSI)", c.kind, got, c.want)
				}
			})
		}
	}
}

func TestStatusIcon_UnknownKind(t *testing.T) {
	pal := NewPalette(false)
	if got := StatusIcon(pal, StatusKind(99)); got != "" {
		t.Errorf("StatusIcon(unknown) = %q, want empty", got)
	}
}
