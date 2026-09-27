package ui

import "testing"

func TestColorEnabled(t *testing.T) {
	cases := []struct {
		name      string
		noColor   string
		force     string
		isTTY     bool
		wantColor bool
	}{
		{"NO_COLOR wins over TTY", "1", "", true, false},
		{"NO_COLOR wins over force", "1", "1", true, false},
		{"force wins over non-TTY", "", "1", false, true},
		{"force=0 does not force", "", "0", false, false},
		{"plain TTY, no overrides", "", "", true, true},
		{"non-TTY, no overrides -> plain fallback", "", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := colorEnabled(c.noColor, c.force, c.isTTY)
			if got != c.wantColor {
				t.Errorf("colorEnabled(%q, %q, %v) = %v, want %v", c.noColor, c.force, c.isTTY, got, c.wantColor)
			}
		})
	}
}
