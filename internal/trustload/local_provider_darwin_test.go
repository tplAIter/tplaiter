//go:build darwin

package trustload

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
