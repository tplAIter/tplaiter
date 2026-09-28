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

// spinnerFrames — animation frames (bubbles/spinner.MiniDot's curated frame set,
// without creating a full bubbletea.Program for one progress indicator).
var spinnerFrames = spinner.MiniDot

// Spinner — minimal progress indicator for long operations (repo add clone, repo
// update fetch, update/new render). Animation is ONLY on TTY (see [Spinner.tty]);
// otherwise Start prints one ordinary line without carriage return, as callers
// did before Spinner (see internal/repo/manager.go usage).
//
// Writes to w, which should be stderr (the contract says the spinner writes to
// stderr so scripts/tests can parse stdout undisturbed).
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

// NewSpinner creates a spinner writing to w (usually cmd.ErrOrStderr()).
func NewSpinner(w io.Writer, pal Palette) *Spinner {
	return &Spinner{w: w, pal: pal, tty: isTerminalWriter(w)}
}

// Start begins animation with a message rendered by format/a (fmt.Sprintf).
// Without TTY it prints once (see Spinner docs). A repeated Start stops the
// previous animation first.
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

// Stop stops animation (if any) and clears its line so the next Fprintln starts
// cleanly. Without TTY it is a no-op: Start printed once and there is nothing to erase.
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

// isTerminalWriter reports whether w is connected to a terminal. Non-*os.File
// writers (including test io.Writers such as bytes.Buffer and cmd.ErrOrStderr
// substitutes) are always non-TTY, enabling Spinner unit tests without a real TTY.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
