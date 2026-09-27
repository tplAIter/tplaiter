package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarkdown_PlainFallback(t *testing.T) {
	src := "# Title\n\nSome **bold** text.\n"
	var buf bytes.Buffer
	if err := Markdown(&buf, []byte(src), false); err != nil {
		t.Fatalf("Markdown(colorEnabled=false): %v", err)
	}
	if buf.String() != src {
		t.Errorf("Markdown(colorEnabled=false) = %q, want passthrough %q", buf.String(), src)
	}
}

func TestMarkdown_PlainFallback_AddsTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, []byte("no trailing newline"), false); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("Markdown(colorEnabled=false) = %q, want trailing newline appended", buf.String())
	}
}

func TestMarkdown_ColorEnabledRendersWithoutError(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, []byte("# Title\n\nSome **bold** text.\n"), true); err != nil {
		t.Fatalf("Markdown(colorEnabled=true): %v", err)
	}
	if !strings.Contains(buf.String(), "Title") {
		t.Errorf("Markdown(colorEnabled=true) output does not contain source content:\n%s", buf.String())
	}
}
