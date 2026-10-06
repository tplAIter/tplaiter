//go:build darwin

package trustload

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLocalEndpointDarwinAccountAndNamespace(t *testing.T) {
	parent, err := os.MkdirTemp("/private/tmp", "lp-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	socket := filepath.Join(parent, "session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		} else {
			accepted <- nil
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	endpoint, err := openLocalEndpoint(ctx, socket, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.close()
	c := <-accepted
	if c == nil {
		t.Fatal("accept")
	}
	defer c.Close()
	if endpoint.uid != uint32(os.Geteuid()) || endpoint.pid != os.Getpid() {
		t.Fatal("kernel peer account/process observation")
	}
	if err = endpoint.recheck(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(socket, socket+".old"); err != nil {
		t.Fatal(err)
	}
	if err = endpoint.recheck(); err == nil {
		t.Fatal("changed pathname accepted")
	}
	var unavailable *LocalProviderUnavailableError
	if errors.As(err, &unavailable) {
		t.Fatal("changed pathname classified as unavailable")
	}
}

func TestLocalEndpointDarwinRefusals(t *testing.T) {
	parent, err := os.MkdirTemp("/private/tmp", "lp-refuse-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	socket := filepath.Join(parent, "session.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = openLocalEndpoint(ctx, socket, uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("foreign UID accepted")
	}
	link := filepath.Join(parent, "alias.sock")
	if err = os.Symlink(socket, link); err != nil {
		t.Fatal(err)
	}
	if _, err = openLocalEndpoint(ctx, link, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err = openLocalEndpoint(ctx, socket, uint32(os.Geteuid())); err == nil {
		t.Fatal("broad parent accepted")
	}
}

func TestLocalEndpointUnavailableClassification(t *testing.T) {
	parent, err := os.MkdirTemp("/private/tmp", "lp-unavailable-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	socket := filepath.Join(parent, "session.sock")
	uid := uint32(os.Geteuid())
	check := func(t *testing.T, ctx context.Context, path string, owner uint32, wantUnavailable bool) {
		t.Helper()
		endpoint, err := openLocalEndpoint(ctx, path, owner)
		if err == nil || !errors.Is(err, ErrLocalProvider) {
			t.Fatalf("expected compatible refusal, got %v", err)
		}
		var unavailable *LocalProviderUnavailableError
		if errors.As(err, &unavailable) != wantUnavailable {
			t.Fatalf("unavailable classification = %v, want %v", unavailable != nil, wantUnavailable)
		}
		if endpoint != nil {
			if !endpoint.closed || endpoint.conn != nil {
				t.Fatal("failed acquisition retained an open endpoint")
			}
			for _, held := range endpoint.held {
				var st unix.Stat_t
				if err := unix.Fstat(held.fd, &st); !errors.Is(err, unix.EBADF) {
					t.Fatal("failed acquisition retained a descriptor")
				}
			}
		}
	}
	t.Run("safe-missing-leaf", func(t *testing.T) {
		check(t, context.Background(), socket, uid, true)
	})
	t.Run("unserved-owned-socket", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrUnix{Name: socket}); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(socket)
		// No Listen or Accept: this is a neutral bound-but-unserved endpoint.
		check(t, context.Background(), socket, uid, true)
	})
	t.Run("unsafe-parent-missing-leaf", func(t *testing.T) {
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700)
		check(t, context.Background(), socket, uid, false)
	})
	t.Run("missing-intermediate", func(t *testing.T) {
		check(t, context.Background(), filepath.Join(parent, "missing", "session.sock"), uid, false)
	})
	t.Run("dangling-symlink", func(t *testing.T) {
		if err := os.Symlink("absent.sock", socket); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(socket)
		check(t, context.Background(), socket, uid, false)
	})
	t.Run("regular-leaf", func(t *testing.T) {
		if err := os.WriteFile(socket, []byte("neutral"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(socket)
		check(t, context.Background(), socket, uid, false)
	})
	t.Run("foreign-requested-uid", func(t *testing.T) {
		check(t, context.Background(), socket, uid+1, false)
	})
	t.Run("canceled-context-missing-leaf", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		check(t, ctx, socket, uid, false)
	})
	t.Run("changed-held-name", func(t *testing.T) {
		if err := os.WriteFile(socket, []byte("neutral"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(socket)
		fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, "session.sock", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		endpoint := &localEndpoint{held: []localPathObservation{{fd: fd, name: "session.sock", stat: st}}}
		defer endpoint.close()
		if err := os.Rename(socket, socket+".old"); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(socket + ".old")
		err = endpoint.recheck()
		var unavailable *LocalProviderUnavailableError
		if !errors.Is(err, ErrLocalProvider) || errors.As(err, &unavailable) {
			t.Fatal("changed held identity did not retain authentication refusal")
		}
	})
}
