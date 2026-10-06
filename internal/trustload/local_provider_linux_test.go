//go:build linux

package trustload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func assertLinuxEndpointClosed(t *testing.T, p *localEndpoint) {
	t.Helper()
	if p == nil {
		return
	}
	if !p.closed {
		t.Fatal("endpoint remained open")
	}
	for _, held := range p.held {
		var st unix.Stat_t
		if err := unix.Fstat(held.fd, &st); !errors.Is(err, unix.EBADF) {
			t.Fatal("held descriptor remained open", err)
		}
	}
}

func TestLocalEndpointLinuxAcquisition(t *testing.T) {
	parent, err := os.MkdirTemp("/tmp", "lp-linux-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	path := filepath.Join(parent, "session.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	listener.SetDeadline(time.Now().Add(time.Second))
	accepted := make(chan *net.UnixConn, 1)
	go func() { c, _ := listener.AcceptUnix(); accepted <- c }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, err := openLocalEndpoint(ctx, path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	c := <-accepted
	if c == nil {
		t.Fatal("neutral accept failed")
	}
	defer c.Close()
	if p.uid != uint32(os.Geteuid()) || p.pid != os.Getpid() {
		t.Fatal("actual kernel UID/PID mismatch")
	}
	if err := p.recheck(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	err = p.recheck()
	var unavailable *LocalProviderUnavailableError
	if !errors.Is(err, ErrLocalProvider) || errors.As(err, &unavailable) {
		t.Fatal("changed held namespace became availability")
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	assertLinuxEndpointClosed(t, p)
	if err := p.close(); err != nil {
		t.Fatal("second close", err)
	}
	if _, err := os.Lstat(path + ".old"); err != nil {
		t.Fatal("client removed server-owned leaf")
	}
}

func TestLocalEndpointLinuxUnavailableRefusals(t *testing.T) {
	parent, err := os.MkdirTemp("/tmp", "lp-linux-refuse-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	path := filepath.Join(parent, "session.sock")
	uid := uint32(os.Geteuid())
	check := func(t *testing.T, path string, owner uint32, want bool) {
		t.Helper()
		p, err := openLocalEndpoint(context.Background(), path, owner)
		var unavailable *LocalProviderUnavailableError
		if !errors.Is(err, ErrLocalProvider) || errors.As(err, &unavailable) != want {
			t.Fatal("refusal classification", err, want)
		}
		assertLinuxEndpointClosed(t, p)
	}
	t.Run("safe-final-absence", func(t *testing.T) { check(t, path, uid, true) })
	t.Run("bound-unserved", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		check(t, path, uid, true)
	})
	t.Run("root-direct-is-refused", func(t *testing.T) { check(t, "/neutral-provider-root.sock", uid, false) })
	t.Run("unsafe-final-parent", func(t *testing.T) {
		if err := os.Chmod(parent, 0755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0700)
		check(t, path, uid, false)
	})
	t.Run("missing-intermediate", func(t *testing.T) { check(t, filepath.Join(parent, "absent", "session.sock"), uid, false) })
	t.Run("dangling-alias", func(t *testing.T) {
		if err := os.Symlink("absent.sock", path); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		check(t, path, uid, false)
	})
	t.Run("regular-leaf", func(t *testing.T) {
		if err := os.WriteFile(path, []byte("neutral"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		check(t, path, uid, false)
	})
	t.Run("foreign-requested-uid", func(t *testing.T) { check(t, path, uid+1, false) })
}

func TestLocalEndpointLinuxPredicatesAndDialCauses(t *testing.T) {
	t.Log("Synthetic predicate/mixed-error counters only; not foreign-peer or actual dial observations.")
	uid := uint32(1234)
	for _, tc := range []struct {
		name        string
		st          unix.Stat_t
		final, want bool
	}{
		{"safe-root-ancestor", unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 0}, false, true},
		{"unsafe-root-writable", unix.Stat_t{Mode: unix.S_IFDIR | 0777, Uid: 0}, false, false},
		{"root-sticky-ancestor", unix.Stat_t{Mode: unix.S_IFDIR | 0777 | unix.S_ISVTX, Uid: 0}, false, true},
		{"root-not-selected-final-parent", unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: 0}, true, false},
		{"broad-final-parent", unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: uid}, true, false},
		{"selected-final-parent", unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if linuxDirectoryAllowed(tc.st, uid, tc.final) != tc.want {
				t.Fatal("directory predicate")
			}
		})
	}
	for _, peer := range []*unix.Ucred{nil, {Pid: 0, Uid: uid}, {Pid: -1, Uid: uid}, {Pid: 1, Uid: uid + 1}} {
		if linuxPeerAllowed(peer, uid) {
			t.Fatal("synthetic invalid peer predicate accepted")
		}
	}
	if !linuxPeerAllowed(&unix.Ucred{Pid: 1, Uid: uid}, uid) {
		t.Fatal("synthetic valid peer predicate refused")
	}
	live := context.Background()
	canceled, cancel := context.WithCancel(live)
	cancel()
	expired, stop := context.WithDeadline(live, time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		err, want error
		available bool
	}{
		{"actual-shape-cancel", canceled, &net.OpError{Op: "dial", Net: "unix", Err: context.Canceled}, context.Canceled, false},
		{"wrapped-deadline", expired, fmt.Errorf("neutral: %w", context.DeadlineExceeded), context.DeadlineExceeded, false},
		{"canceled-context-unrelated-error", canceled, errors.New("neutral unrelated failure"), ErrLocalProvider, false},
		{"canceled-refused", canceled, unix.ECONNREFUSED, ErrLocalProvider, false},
		{"mixed-refused-and-cancel", canceled, errors.Join(unix.ECONNREFUSED, context.Canceled), ErrLocalProvider, false},
		{"mixed-opaque-and-cancel", canceled, errors.Join(errors.New("neutral"), context.Canceled), ErrLocalProvider, false},
		{"live-refused", live, unix.ECONNREFUSED, ErrLocalProvider, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &localEndpoint{}
			got := linuxDialFailure(tc.ctx, p, tc.err)
			var unavailable *LocalProviderUnavailableError
			if !errors.Is(got, tc.want) || errors.As(got, &unavailable) != tc.available {
				t.Fatal("synthetic dial classification", got)
			}
		})
	}
	for _, errno := range []error{unix.EACCES, unix.EPERM, unix.ELOOP, unix.ENOTSOCK, unix.ENOENT, unix.ENOTDIR} {
		got := linuxDialFailure(canceled, &localEndpoint{}, errors.Join(errno, context.Canceled))
		var unavailable *LocalProviderUnavailableError
		if got != ErrLocalProvider || errors.As(got, &unavailable) {
			t.Fatal("unsafe errno lost precedence", errno, got)
		}
	}
	got := linuxDialFailure(canceled, &localEndpoint{closed: true}, context.Canceled)
	if got != ErrLocalProvider {
		t.Fatal("unsafe namespace lost precedence", got)
	}
}

func TestLocalProviderLinuxPartialWrite(t *testing.T) {
	p, peer, held := lifetimeCarrier(t, time.Second)
	if err := p.endpoint.conn.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := p.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 1<<20)
	for i := range body {
		body[i] = byte(i % 251)
	}
	n, err := p.Write(body)
	var timeout net.Error
	if n <= 0 || n >= len(body) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("actual partial write not established", n, err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i] != body[i] {
			t.Fatal("delivered prefix differs")
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	assertLifetimeClosed(t, p, held)
	t.Logf("actual neutral delivered prefix=%d; terminal write timeout", n)
}
