package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// spinnerFrames — набор кадров анимации (bubbles/spinner.MiniDot: тот же
// curated frame-set, что charm использует в bubbletea-приложениях, без
// заведения полноценной bubbletea.Program для одного индикатора прогресса).
var spinnerFrames = spinner.MiniDot

// Spinner — минимальный индикатор прогресса длинных операций (repo add
// clone, repo update fetch, update/new рендер). Анимация — ТОЛЬКО при TTY
// (см. [Spinner.tty]); иначе Start печатает сообщение один раз как обычную
// строку без возврата каретки — то же самое, что вызывающий код делал до
// появления Spinner (см. usage в internal/repo/manager.go).
//
// Пишет в переданный w, который должен быть stderr (реализация реализацию, п.5:
// "спиннер пишет в stderr", чтобы не мешать разбору stdout скриптами/тестами).
type Spinner struct {
	w   io.Writer
	pal Palette
	tty bool

	mu      sync.Mutex
	ticker  *time.Ticker
	done    chan struct{}
	stopped chan struct{}
	frame   int
	label   string
}

// NewSpinner создаёт спиннер, пишущий в w (обычно cmd.ErrOrStderr()).
func NewSpinner(w io.Writer, pal Palette) *Spinner {
	return &Spinner{w: w, pal: pal, tty: isTerminalWriter(w)}
}

// Start начинает анимацию с сообщением, отрендеренным по format/a (fmt.Sprintf).
// Без TTY — просто печатает сообщение один раз (см. doc Spinner). Повторный
// Start без предшествующего Stop останавливает предыдущую анимацию.
func (s *Spinner) Start(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)

	s.mu.Lock()
	s.label = msg
	s.mu.Unlock()

	if !s.tty {
		fmt.Fprintln(s.w, msg)
		return
	}

	if s.done != nil {
		s.stopAnimation()
	}
	s.done = make(chan struct{})
	s.stopped = make(chan struct{})
	s.ticker = time.NewTicker(spinnerFrames.FPS)
	go s.loop(s.ticker, s.done, s.stopped)
}

func (s *Spinner) loop(ticker *time.Ticker, done, stopped chan struct{}) {
	defer close(stopped)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			s.mu.Lock()
			frame := spinnerFrames.Frames[s.frame%len(spinnerFrames.Frames)]
			s.frame++
			label := s.label
			s.mu.Unlock()
			fmt.Fprintf(s.w, "\r%s%s", s.pal.Muted(frame), label)
		}
	}
}

// Stop останавливает анимацию (если она была) и очищает её строку, чтобы
// следующий Fprintln начинался с чистого начала строки. Без TTY — no-op:
// Start уже напечатал сообщение один раз, стирать нечего.
func (s *Spinner) Stop() {
	if !s.tty || s.done == nil {
		return
	}
	s.mu.Lock()
	label := s.label
	s.mu.Unlock()

	s.stopAnimation()

	frameWidth := lipgloss.Width(spinnerFrames.Frames[0])
	clearWidth := frameWidth + lipgloss.Width(label)
	fmt.Fprintf(s.w, "\r%s\r", strings.Repeat(" ", clearWidth))
}

func (s *Spinner) stopAnimation() {
	s.ticker.Stop()
	close(s.done)
	<-s.stopped
	s.ticker = nil
	s.done = nil
	s.stopped = nil
}

// isTerminalWriter сообщает, подключён ли w к терминалу. Не-*os.File (в
// частности, любой io.Writer из тестов — bytes.Buffer, cmd.ErrOrStderr()
// подмена и т.п.) всегда считается не-TTY — этим и обеспечивается юнит-
// тестируемость Spinner без реальной подмены изолятора TTY.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
