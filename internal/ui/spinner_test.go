package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestSpinner_NonTTY_NoAnimation проверяет контракт "спиннер показывать
// ТОЛЬКО в TTY" (реализация реализацию): bytes.Buffer никогда не *os.File, поэтому
// isTerminalWriter(w) == false — Start должен просто напечатать сообщение
// один раз, без анимации, без \r, Stop не должен ничего дописывать.
func TestSpinner_NonTTY_NoAnimation(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf, NewPalette(false))

	sp.Start("клонирую %s", "repo")
	if got := buf.String(); got != "клонирую repo\n" {
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
	sp.Stop() // не должен паниковать при отсутствии предшествующего Start
	if buf.Len() != 0 {
		t.Errorf("Stop() without Start wrote %q, want nothing", buf.String())
	}
}

// TestSpinner_IsTerminalWriter_FalseForNonFile проверяет саму детекцию TTY,
// на которой построена тестируемость Spinner (подмена isTTY через тип w,
// без реальной TTY-подделки — см. doc isTerminalWriter).
func TestSpinner_IsTerminalWriter_FalseForNonFile(t *testing.T) {
	if isTerminalWriter(&bytes.Buffer{}) {
		t.Error("isTerminalWriter(*bytes.Buffer) = true, want false")
	}
}

// TestSpinner_AnimationDoesNotBlock проверяет только то, что Start/Stop не
// виснут и не паникуют при принудительно включённой анимации (используем
// приватное поле tty напрямую — конструктор всегда возвращает tty=false для
// io.Writer, не являющегося *os.File).
func TestSpinner_AnimationDoesNotBlock(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf, NewPalette(false))
	sp.tty = true // симулируем TTY для проверки жизненного цикла анимации

	sp.Start("работаю")
	time.Sleep(150 * time.Millisecond) // дать анимации хотя бы один тик (MiniDot FPS ~83ms)
	sp.Stop()

	if !strings.Contains(buf.String(), "работаю") {
		t.Errorf("animated Start() output does not contain label: %q", buf.String())
	}
}
