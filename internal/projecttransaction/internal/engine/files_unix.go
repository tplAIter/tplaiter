//go:build darwin || linux

package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func fileID(i os.FileInfo) Identity {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}
	}
	return Identity{deviceID(s.Dev), s.Ino}
}

func singleLink(i os.FileInfo) bool { s, ok := i.Sys().(*syscall.Stat_t); return ok && s.Nlink == 1 }
func readNoFollow() int             { return os.O_RDONLY | syscall.O_NOFOLLOW }
func exclusiveFlags() int           { return os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW }
func writeLockFlags() int           { return os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW }
func lock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrActive
	}
	return err
}

// Open every parent without following symlinks; validate each opened descriptor
// against its sealed original/new directory identity, including a swapped parent.
func (t *Transaction) parent(name string) (int, string, error) {
	fd, err := unix.Open(t.plan.Material.Root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", err
	}
	check := func(fd int, want Identity) error {
		var s unix.Stat_t
		if err := unix.Fstat(fd, &s); err != nil || (Identity{deviceID(s.Dev), s.Ino}) != want {
			return ErrConflict
		}
		return nil
	}
	if err := check(fd, t.plan.RootIdentity); err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	parent := filepath.Dir(name)
	prefix := ""
	if parent != "." {
		for _, part := range strings.Split(filepath.ToSlash(parent), "/") {
			next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			unix.Close(fd)
			if err != nil {
				return -1, "", err
			}
			fd = next
			if prefix == "" {
				prefix = part
			} else {
				prefix += "/" + part
			}
			want := Identity{}
			if original, ok := t.plan.Material.Before[prefix]; ok {
				want = Identity{original.Device, original.Inode}
			} else {
				for _, step := range t.state.Steps {
					if step.Path == prefix {
						want = step.AfterIdentity
					}
				}
			}
			if want.Inode == 0 || check(fd, want) != nil {
				unix.Close(fd)
				return -1, "", ErrConflict
			}
		}
	}
	return fd, filepath.Base(name), nil
}

func (t *Transaction) publish(s step, exchange bool) error {
	target, name, err := t.parent(s.Path)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	images, err := unix.Open(t.images, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(images)
	var imageStat unix.Stat_t
	if err := unix.Fstat(images, &imageStat); err != nil || (Identity{deviceID(imageStat.Dev), imageStat.Ino}) != t.state.ImageIdentity {
		return ErrConflict
	}
	if exchange {
		err = exchangeAt(images, s.Slot, target, name)
	} else {
		err = exclusiveRenameAt(images, s.Slot, target, name)
	}
	if err != nil {
		return err
	}
	return errors.Join(unix.Fsync(target), unix.Fsync(images))
}

func (t *Transaction) quarantine(s step) error {
	target, name, err := t.parent(s.Path)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	images, err := unix.Open(t.images, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(images)
	var imageStat unix.Stat_t
	if err := unix.Fstat(images, &imageStat); err != nil || (Identity{deviceID(imageStat.Dev), imageStat.Ino}) != t.state.ImageIdentity {
		return ErrConflict
	}
	if err := exclusiveRenameAt(target, name, images, s.Slot); err != nil {
		return err
	}
	return errors.Join(unix.Fsync(target), unix.Fsync(images))
}

// Serialize with the real existing-project and home-registry writers. Neither
// lock bytes nor a lease establish ownership; beforeimage checks remain required.
func (t *Transaction) acquireWriterLocks() error {
	parent, name, err := t.parent(".tplaiter/update.lock")
	if err != nil {
		return err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW, 0o600)
	unix.Close(parent)
	if err != nil {
		return err
	}
	project := os.NewFile(uintptr(fd), filepath.Join(t.plan.Material.Root, ".tplaiter/update.lock"))
	t.writerLocks = append(t.writerLocks, project)
	home, err := unix.Open(t.plan.Material.Home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	var homeStat unix.Stat_t
	if err := unix.Fstat(home, &homeStat); err != nil || (Identity{deviceID(homeStat.Dev), homeStat.Ino}) != t.plan.HomeIdentity {
		unix.Close(home)
		return ErrConflict
	}
	fd, err = unix.Openat(home, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW, 0o600)
	unix.Close(home)
	if err != nil {
		return err
	}
	registry := os.NewFile(uintptr(fd), filepath.Join(t.plan.Material.Home, ".lock"))
	t.writerLocks = append(t.writerLocks, registry)
	for _, f := range t.writerLocks {
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !singleLink(info) {
			return ErrConflict
		}
		if err := lock(f); err != nil {
			return err
		}
	}
	return nil
}
