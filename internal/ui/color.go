package ui

import (
	"os"

	"golang.org/x/term"
)

// ColorEnabled reports whether color output is enabled for the current process's
// stdout. Rules, in priority order:
//  1. NO_COLOR is set (to any value; see https://no-color.org/) -> false;
//  2. CLICOLOR_FORCE is set and not "0" -> true, even if stdout is not a TTY;
//  3. otherwise true only when stdout is a terminal.
func ColorEnabled() bool {
	return colorEnabled(os.Getenv("NO_COLOR"), os.Getenv("CLICOLOR_FORCE"), isTerminal(os.Stdout))
}

// colorEnabled is a pure, side-effect-free function extracted for unit tests.
func colorEnabled(noColor, forceColor string, stdoutIsTTY bool) bool {
	if noColor != "" {
		return false
	}
	if forceColor != "" && forceColor != "0" {
		return true
	}
	return stdoutIsTTY
}

// isTerminal reports whether f is attached to a terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
