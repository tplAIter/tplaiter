//go:build linux

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
	if ctx == nil || uid != uint32(os.Geteuid()) || !absolutePath(path) || len(path) > 103 || filepath.Dir(path) == "/" {
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
	if unix.Fstat(fd, &root) != nil || !linuxDirectoryAllowed(root, uid, false) {
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
		if !linuxDirectoryAllowed(st, uid, i == len(components)-2) {
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
		return p, linuxDialFailure(ctx, p, e)
	}
	var ok bool
	p.conn, ok = conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return p, ErrLocalProvider
	}
	raw, e := p.conn.SyscallConn()
	if e != nil {
		return p, ErrLocalProvider
	}
	var peerErr error
	e = raw.Control(func(fd uintptr) {
		peer, er := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if er != nil || !linuxPeerAllowed(peer, uid) {
			peerErr = ErrLocalProvider
			return
		}
		p.uid = peer.Uid
		p.pid = int(peer.Pid)
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

// Root uses the ancestor rule; a root-direct socket is refused before acquisition.
// Every non-root final parent must satisfy the stricter account-owned 0700 rule.
func linuxDirectoryAllowed(st unix.Stat_t, uid uint32, final bool) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uid) {
		return false
	}
	if final {
		return st.Uid == uid && st.Mode&0o777 == 0o700
	}
	return st.Mode&0o022 == 0 || (st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)
}

func linuxPeerAllowed(peer *unix.Ucred, uid uint32) bool {
	return peer != nil && peer.Uid == uid && peer.Pid > 0
}

// Called only with the actual DialContext failure. Namespace and unsafe errno
// refusal win even when cancellation races. Joined synthetic errors are not a
// single cancellation cause and cannot replace the observed failure.
func linuxDialFailure(ctx context.Context, p *localEndpoint, dialErr error) error {
	if err := p.recheck(); err != nil {
		return err
	}
	for _, unsafe := range []error{unix.EACCES, unix.EPERM, unix.ELOOP, unix.ENOTSOCK, unix.ENOENT, unix.ENOTDIR} {
		if errors.Is(dialErr, unsafe) {
			return ErrLocalProvider
		}
	}
	for current := dialErr; current != nil; current = errors.Unwrap(current) {
		if _, joined := current.(interface{ Unwrap() []error }); joined {
			return ErrLocalProvider
		}
	}
	if errors.Is(dialErr, unix.ECONNREFUSED) {
		if ctx.Err() == nil {
			return localProviderUnavailable()
		}
		return ErrLocalProvider
	}
	if cause := ctx.Err(); cause != nil && errors.Is(dialErr, cause) {
		return cause
	}
	return ErrLocalProvider
}
