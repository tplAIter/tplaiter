//go:build darwin || linux

package ossinstall

import (
	"bytes"
	"context"
	"errors"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
)

func writeExecutionCAS(ctx context.Context, root, ref string, b []byte) error {
	root += "/sha256"
	if e := ctx.Err(); e != nil {
		return e
	}
	if evidencecas.Digest(b) != ref || len(b) > 1<<20 || !strings.HasPrefix(root, "/") {
		return errors.New("TRUST_APPROVAL_MISMATCH")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	for _, p := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if p == "" || p == "." || p == ".." {
			unix.Close(fd)
			return errors.New("unsafe CAS root")
		}
		n, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return e
		}
		fd = n
	}
	defer unix.Close(fd)
	h := strings.TrimPrefix(ref, "sha256:")
	if e := unix.Mkdirat(fd, h[:2], 0700); e != nil && !errors.Is(e, unix.EEXIST) {
		return e
	}
	dir, e := unix.Openat(fd, h[:2], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(dir)
	out, e := unix.Openat(dir, h[2:], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(e, unix.EEXIST) {
		f, e := unix.Openat(dir, h[2:], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		file := os.NewFile(uintptr(f), "public CAS")
		defer file.Close()
		info, e := file.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("unsafe CAS object")
		}
		old, e := io.ReadAll(io.LimitReader(file, 1<<20+1))
		if e != nil || !bytes.Equal(old, b) {
			return errors.New("CAS collision")
		}
		return nil
	}
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(out), "public approval")
	_, e = file.Write(b)
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = unix.Fsync(dir)
	}
	if e != nil {
		_ = unix.Unlinkat(dir, h[2:], 0)
	}
	return e
}
