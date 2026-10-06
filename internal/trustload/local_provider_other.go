//go:build !darwin && !linux

package trustload

import (
	"context"
	"net"
)

type localEndpoint struct {
	conn net.Conn
	uid  uint32
	pid  int
}

func openLocalEndpoint(context.Context, string, uint32) (*localEndpoint, error) {
	return nil, ErrLocalUnsupported
}
func (p *localEndpoint) recheck() error { return ErrLocalUnsupported }
func (p *localEndpoint) close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}
