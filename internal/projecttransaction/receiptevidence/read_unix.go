//go:build darwin || linux

package receiptevidence

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type physicalFact struct {
	device, inode                            uint64
	size                                     int64
	mode                                     uint32
	links                                    uint64
	mtimeSec, mtimeNsec, ctimeSec, ctimeNsec int64
}
type directoryRef struct {
	fd            int
	name          string
	device, inode uint64
	mode          uint32
}
type directoryHandle struct{ refs []directoryRef }

func signedDevice[T ~int32 | ~uint64](v T) uint64 { return uint64(v) }
func factOf(s unix.Stat_t) physicalFact {
	return physicalFact{signedDevice(s.Dev), s.Ino, s.Size, uint32(s.Mode), uint64(s.Nlink), s.Mtim.Sec, s.Mtim.Nsec, s.Ctim.Sec, s.Ctim.Nsec}
}
func (d *directoryHandle) close() {
	if d != nil {
		for i := len(d.refs) - 1; i >= 0; i-- {
			unix.Close(d.refs[i].fd)
		}
		d.refs = nil
	}
}
func openDirectory(ctx context.Context, name string) (*directoryHandle, error) {
	if ctx == nil || !absoluteClean(name) {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrAuthentication
	}
	d := &directoryHandle{}
	fail := func(e error) (*directoryHandle, error) { d.close(); return nil, e }
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		unix.Close(fd)
		return nil, ErrAuthentication
	}
	d.refs = append(d.refs, directoryRef{fd: fd, name: "/", device: signedDevice(stat.Dev), inode: stat.Ino, mode: uint32(stat.Mode)})
	if name != "/" {
		for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			fd, err = unix.Openat(d.refs[len(d.refs)-1].fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fail(ErrAuthentication)
			}
			if unix.Fstat(fd, &stat) != nil {
				unix.Close(fd)
				return fail(ErrAuthentication)
			}
			d.refs = append(d.refs, directoryRef{fd: fd, name: part, device: signedDevice(stat.Dev), inode: stat.Ino, mode: uint32(stat.Mode)})
		}
	}
	if err = d.check(); err != nil {
		return fail(err)
	}
	return d, nil
}
func (d *directoryHandle) check() error {
	if d == nil || len(d.refs) == 0 {
		return ErrClosed
	}
	for i, r := range d.refs {
		var held, named unix.Stat_t
		if unix.Fstat(r.fd, &held) != nil || uint32(held.Mode) != r.mode || held.Mode&unix.S_IFMT != unix.S_IFDIR || signedDevice(held.Dev) != r.device || held.Ino != r.inode {
			return ErrAuthentication
		}
		if i == 0 {
			if unix.Lstat("/", &named) != nil {
				return ErrAuthentication
			}
		} else if unix.Fstatat(d.refs[i-1].fd, r.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrAuthentication
		}
		if uint32(named.Mode) != r.mode || named.Mode&unix.S_IFMT != unix.S_IFDIR || signedDevice(named.Dev) != r.device || named.Ino != r.inode {
			return ErrAuthentication
		}
	}
	return nil
}
func (d *directoryHandle) private() error {
	if err := d.check(); err != nil {
		return err
	}
	if d.refs[len(d.refs)-1].mode&0o7777 != 0o700 {
		return ErrAuthentication
	}
	return nil
}
func regular(s unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFREG && uint32(s.Mode)&0o7777 == 0o600 && s.Nlink == 1 && s.Ino != 0
}
func (d *directoryHandle) read(ctx context.Context, name string, max int64, budget *int64) ([]byte, physicalFact, error) {
	var zero physicalFact
	if ctx == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, zero, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	if err := d.check(); err != nil {
		return nil, zero, err
	}
	parent := d.refs[len(d.refs)-1].fd
	var observed unix.Stat_t
	if unix.Fstatat(parent, name, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !regular(observed) || observed.Size < 0 || observed.Size > max {
		return nil, zero, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, zero, ErrAuthentication
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var held unix.Stat_t
	if unix.Fstat(fd, &held) != nil || !regular(held) || factOf(observed) != factOf(held) {
		return nil, zero, ErrAuthentication
	}
	size := held.Size
	// Charge raw read work before allocating, including failed read attempts.
	if budget != nil {
		if size > *budget {
			return nil, zero, ErrAuthentication
		}
		*budget -= size
	}
	raw := make([]byte, int(size))
	for offset := 0; offset < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, zero, err
		}
		end := offset + (64 << 10)
		if end > len(raw) {
			end = len(raw)
		}
		n, e := f.Read(raw[offset:end])
		offset += n
		if e != nil || n == 0 {
			return nil, zero, ErrAuthentication
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	var sentinel [1]byte
	n, e := f.Read(sentinel[:])
	if n != 0 || !errors.Is(e, io.EOF) {
		return nil, zero, ErrAuthentication
	}
	var after, named unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !regular(after) || !regular(named) || factOf(held) != factOf(after) || factOf(held) != factOf(named) {
		return nil, zero, ErrAuthentication
	}
	if err = d.check(); err != nil {
		return nil, zero, err
	}
	if err = ctx.Err(); err != nil {
		return nil, zero, err
	}
	return raw, factOf(held), nil
}
func readPhysical(ctx context.Context, name string, max int64, budget *int64) ([]byte, physicalFact, error) {
	d, err := openDirectory(ctx, filepath.Dir(name))
	if err != nil {
		return nil, physicalFact{}, err
	}
	defer d.close()
	return d.read(ctx, filepath.Base(name), max, budget)
}

func (d *directoryHandle) observe(name string) (physicalFact, error) {
	if err := d.check(); err != nil {
		return physicalFact{}, err
	}
	var stat unix.Stat_t
	if unix.Fstatat(d.refs[len(d.refs)-1].fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || !regular(stat) {
		return physicalFact{}, ErrAuthentication
	}
	return factOf(stat), nil
}
