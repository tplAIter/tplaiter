//go:build darwin

package trustload

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type localPathObservation struct {
	fd   int
	name string
	stat unix.Stat_t
}
type localEndpoint struct {
	mu     sync.Mutex
	conn   *net.UnixConn
	uid    uint32
	pid    int
	held   []localPathObservation
	closed bool
}

func sameLocalStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid
}

func openLocalEndpoint(ctx context.Context, path string, uid uint32) (p *localEndpoint, err error) {
	if ctx == nil || uid != uint32(os.Geteuid()) || !absolutePath(path) || len(path) > 103 {
		return nil, ErrLocalProvider
	}
	p = &localEndpoint{}
	defer func() {
		if err != nil {
			_ = p.close()
		}
	}()
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return p, ErrLocalProvider
	}
	var root unix.Stat_t
	if unix.Fstat(fd, &root) != nil {
		_ = unix.Close(fd)
		return p, ErrLocalProvider
	}
	p.held = append(p.held, localPathObservation{fd: fd, stat: root})
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range components {
		if name == "" || name == "." || name == ".." {
			return p, ErrLocalProvider
		}
		var st unix.Stat_t
		if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			if i == len(components)-1 && errors.Is(e, unix.ENOENT) && ctx.Err() == nil {
				if e = p.recheck(); e != nil {
					return p, e
				}
				if ctx.Err() == nil {
					return p, localProviderUnavailable()
				}
			}
			return p, ErrLocalProvider
		}
		if i == len(components)-1 {
			if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid {
				return p, ErrLocalProvider
			}
			p.held = append(p.held, localPathObservation{fd: fd, name: name, stat: st})
			break
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uid) {
			return p, ErrLocalProvider
		}
		final := i == len(components)-2
		if final {
			if st.Uid != uid || st.Mode&0o777 != 0o700 {
				return p, ErrLocalProvider
			}
		} else if st.Mode&0o022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			return p, ErrLocalProvider
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return p, ErrLocalProvider
		}
		var actual unix.Stat_t
		if unix.Fstat(next, &actual) != nil || !sameLocalStat(st, actual) {
			_ = unix.Close(next)
			return p, ErrLocalProvider
		}
		p.held = append(p.held, localPathObservation{fd: next, stat: actual})
		// Also retain the parent-to-child name identity to observe rename/replacement.
		p.held = append(p.held, localPathObservation{fd: fd, name: name, stat: actual})
		fd = next
	}
	if e = p.recheck(); e != nil {
		return p, e
	}
	dialer := net.Dialer{}
	conn, e := dialer.DialContext(ctx, "unix", filepath.Clean(path))
	if e != nil {
		if errors.Is(e, unix.ECONNREFUSED) && ctx.Err() == nil {
			if e = p.recheck(); e != nil {
				return p, e
			}
			if ctx.Err() == nil {
				return p, localProviderUnavailable()
			}
		}
		return p, ErrLocalProvider
	}
	p.conn = conn.(*net.UnixConn)
	raw, e := p.conn.SyscallConn()
	if e != nil {
		return p, ErrLocalProvider
	}
	var peerErr error
	e = raw.Control(func(fd uintptr) {
		peer, er := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if er != nil || peer.Uid != uid {
			peerErr = ErrLocalProvider
			return
		}
		p.uid = peer.Uid
		p.pid, peerErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if e != nil || peerErr != nil || p.pid <= 0 {
		return p, ErrLocalProvider
	}
	if e = p.recheck(); e != nil {
		return p, e
	}
	return p, nil
}

func (p *localEndpoint) recheck() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrLocalProvider
	}
	for _, o := range p.held {
		var st unix.Stat_t
		var err error
		if o.name == "" {
			err = unix.Fstat(o.fd, &st)
		} else {
			err = unix.Fstatat(o.fd, o.name, &st, unix.AT_SYMLINK_NOFOLLOW)
		}
		if err != nil || !sameLocalStat(o.stat, st) {
			return ErrLocalProvider
		}
	}
	return nil
}

func (p *localEndpoint) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var err error
	if p.conn != nil {
		err = p.conn.Close()
	}
	seen := map[int]bool{}
	for _, o := range p.held {
		if !seen[o.fd] {
			seen[o.fd] = true
			_ = unix.Close(o.fd)
		}
	}
	return err
}
