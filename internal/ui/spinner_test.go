package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestSpinner_NonTTY_NoAnimation checks the contract that the spinner is shown
// ONLY on a TTY: bytes.Buffer is never an *os.File, so isTerminalWriter(w) is
// false. Start must print the message once without animation or \r, and Stop
// must append nothing.
func TestSpinner_NonTTY_NoAnimation(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf, NewPalette(false))

	sp.Start("cloning %s", "repo")
	if got := buf.String(); got != "cloning repo\n" {
		t.Errorf("Start() non-TTY output = %q, want plain single line", got)
	}
	if strings.Contains(buf.String(), "\r") {
		t.Errorf("Start() non-TTY output contains \\r, animation must be disabled: %q", buf.String())
	}

	before := buf.String()
	sp.Stop()
	if buf.String() != before {
		t.Errorf("Stop() non-TTY must be a no-op, output changed: %q -> %q", before, buf.String())
	}
}

func TestSpinner_NonTTY_StopWithoutStartIsNoop(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf, NewPalette(false))
	sp.Stop() // must not panic when Start was not called first
	if buf.Len() != 0 {
		t.Errorf("Stop() without Start wrote %q, want nothing", buf.String())
	}
}

// TestSpinner_IsTerminalWriter_FalseForNonFile checks TTY detection, which
// makes Spinner testable by substituting the writer type without faking a real
// TTY; see the isTerminalWriter documentation.
func TestSpinner_IsTerminalWriter_FalseForNonFile(t *testing.T) {
	if isTerminalWriter(&bytes.Buffer{}) {
		t.Error("isTerminalWriter(*bytes.Buffer) = true, want false")
	}
}

// TestSpinner_AnimationDoesNotBlock only checks that Start/Stop do not hang or
// panic when animation is forced (the private tty field is used directly; the
// constructor always returns tty=false for an io.Writer that is not an
// *os.File).
func TestSpinner_AnimationDoesNotBlock(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf, NewPalette(false))
	sp.tty = true // simulate a TTY to check the animation lifecycle

	sp.Start("working")
	time.Sleep(150 * time.Millisecond) // allow at least one animation tick (MiniDot FPS ~83ms)
	sp.Stop()

	if !strings.Contains(buf.String(), "working") {
		t.Errorf("animated Start() output does not contain label: %q", buf.String())
	}
}
