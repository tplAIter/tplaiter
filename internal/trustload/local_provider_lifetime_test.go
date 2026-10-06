//go:build darwin || linux

package trustload

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Connected socket pairs exercise real pollable descriptors without a listener.
func lifetimeCarrier(t *testing.T, duration time.Duration) (*LocalProvider, *net.UnixConn, int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	var connections [2]*net.UnixConn
	for i, fd := range pair {
		file := os.NewFile(uintptr(fd), "neutral-lifetime-pair")
		conn, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections[i] = conn.(*net.UnixConn)
	}
	held, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(held, &st); err != nil {
		t.Fatal(err)
	}
	p := &LocalProvider{expires: time.Now().Add(duration), endpoint: &localEndpoint{conn: connections[0], held: []localPathObservation{{fd: held, stat: st}}}}
	if err := p.armLifetime(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(); connections[1].Close() })
	return p, connections[1], held
}

func assertLifetimeClosed(t *testing.T, p *LocalProvider, held int) {
	t.Helper()
	p.mu.Lock()
	closed := p.closed
	stopped := !p.timer.Stop()
	p.mu.Unlock()
	if !closed || !stopped {
		t.Fatal("carrier or owned timer still live")
	}
	var st unix.Stat_t
	if err := unix.Fstat(held, &st); !errors.Is(err, unix.EBADF) {
		t.Fatal("held descriptor not released", err)
	}
}

func TestLocalProviderFixedLifetime(t *testing.T) {
	t.Run("clear-and-extension-cannot-prolong", func(t *testing.T) {
		p, _, held := lifetimeCarrier(t, 100*time.Millisecond)
		fixed := p.Deadline()
		for _, setter := range []func(time.Time) error{p.SetDeadline, p.SetReadDeadline, p.SetWriteDeadline} {
			if err := setter(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if err := setter(fixed.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		begin := time.Now()
		n, err := p.Read(make([]byte, 1))
		if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expired read delivered data or lost deadline", n, err)
		}
		if time.Since(begin) > time.Second || p.Deadline() != fixed {
			t.Fatal("caller widened fixed acquisition lifetime")
		}
		assertLifetimeClosed(t, p, held)
		if n, err := p.Write([]byte("x")); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expired write", n, err)
		}
		if err := p.Recheck(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expired recheck", err)
		}
		if err := p.SetDeadline(time.Time{}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expired deadline setter", err)
		}
	})
	t.Run("earlier-read-deadline", func(t *testing.T) {
		p, _, _ := lifetimeCarrier(t, time.Second)
		fixed := p.Deadline()
		if err := p.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		_, err := p.Read(make([]byte, 1))
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("earlier read deadline not honored distinctly", err)
		}
		if time.Since(begin) > 500*time.Millisecond || !time.Now().Before(fixed) || p.Deadline() != fixed {
			t.Fatal("read waited for fixed expiry")
		}
	})
	t.Run("earlier-write-deadline-and-backpressure", func(t *testing.T) {
		p, _, _ := lifetimeCarrier(t, time.Second)
		fixed := p.Deadline()
		if err := p.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		_, err := p.Write(make([]byte, 1<<20)) // Peer deliberately consumes no bytes.
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked write lost earlier deadline", err)
		}
		if time.Since(begin) > 500*time.Millisecond || !time.Now().Before(fixed) || p.Deadline() != fixed {
			t.Fatal("write waited for fixed expiry")
		}
	})
	t.Run("timer-releases-idle-resources", func(t *testing.T) {
		p, peer, held := lifetimeCarrier(t, 60*time.Millisecond)
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("idle expiry did not close peer", n, err)
		}
		// Peer EOF can precede the final held-descriptor close by a scheduler turn.
		end := time.Now().Add(time.Second)
		for {
			p.mu.Lock()
			done := p.closed && p.endpoint.closed
			p.mu.Unlock()
			var st unix.Stat_t
			if done && errors.Is(unix.Fstat(held, &st), unix.EBADF) {
				break
			}
			if time.Now().After(end) {
				t.Fatal("idle held descriptor leaked")
			}
			time.Sleep(time.Millisecond)
		}
		assertLifetimeClosed(t, p, held)
		if err := p.Recheck(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("close-stops-timer-and-is-idempotent", func(t *testing.T) {
		p, _, held := lifetimeCarrier(t, 200*time.Millisecond)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := p.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		assertLifetimeClosed(t, p, held)
		sentinel, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer sentinel.Close()
		time.Sleep(time.Until(p.Deadline()) + 20*time.Millisecond)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := sentinel.Stat(); err != nil {
			t.Fatal("late close damaged an independently owned descriptor", err)
		}
		if _, err := p.Read(make([]byte, 1)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("expiry lost after explicit close", err)
		}
	})
}
