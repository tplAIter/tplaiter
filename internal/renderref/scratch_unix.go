//go:build darwin || linux

package renderref

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// scratchDirectory holds both directory descriptors for the whole render. The
// engine receives /dev/fd/<child>, so every path it opens is rooted at the held
// child descriptor rather than at a pathname which could be replaced.
type scratchDirectory struct {
	parent, child         int
	parentFile, childFile *os.File
	name                  string
	enginePath            string
	childIdentity         scratchIdentity
}
type scratchIdentity struct {
	dev, ino uint64
	uid      uint32
	mode     uint32
}

func openScratch(root string) (*scratchDirectory, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("renderref: invalid scratch root")
	}
	final, err := os.Lstat(root)
	if err != nil || !final.IsDir() || final.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("renderref: scratch root unavailable")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(canonical) {
		return nil, errors.New("renderref: scratch root unavailable")
	}
	root = canonical
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("renderref: scratch root unavailable")
	}
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("renderref: invalid scratch root")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, errors.New("renderref: scratch root unavailable")
		}
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(unix.Geteuid()) || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("renderref: unsafe scratch root")
	}
	for i := 0; i < 32; i++ {
		var entropy [16]byte
		if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
			_ = unix.Close(fd)
			return nil, errors.New("renderref: scratch entropy unavailable")
		}
		name := ".tplaiter-preview-" + hex.EncodeToString(entropy[:])
		if err := unix.Mkdirat(fd, name, 0o700); err == unix.EEXIST {
			continue
		} else if err != nil {
			_ = unix.Close(fd)
			return nil, errors.New("renderref: scratch allocation failed")
		}
		child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			_ = unix.Close(fd)
			return nil, errors.New("renderref: scratch allocation failed")
		}
		if err := unix.Fstat(child, &stat); err != nil || stat.Uid != uint32(unix.Geteuid()) || stat.Mode&0o077 != 0 {
			_ = unix.Close(child)
			_ = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			_ = unix.Close(fd)
			return nil, errors.New("renderref: unsafe scratch child")
		}
		enginePath, err := enginePathForFD(child)
		if err != nil {
			_ = unix.Close(child)
			_ = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			_ = unix.Close(fd)
			return nil, errors.New("renderref: engine scratch unavailable")
		}
		return &scratchDirectory{parent: fd, child: child, parentFile: os.NewFile(uintptr(fd), "scratch-parent"), childFile: os.NewFile(uintptr(child), "scratch-child"), name: name, enginePath: enginePath, childIdentity: identity(stat)}, nil
	}
	_ = unix.Close(fd)
	return nil, errors.New("renderref: scratch allocation exhausted")
}

func (s *scratchDirectory) Path() string { return s.enginePath }

// Check is an allocation lifecycle integrity check. It does not claim to
// prevent a concurrent controlling-principal namespace race.
func (s *scratchDirectory) Check() error {
	if s == nil || s.child < 0 {
		return errors.New("renderref: scratch unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(s.child, &stat); err != nil || stat.Uid != uint32(unix.Geteuid()) || stat.Mode&0o077 != 0 || identity(stat) != s.childIdentity {
		return errors.New("renderref: scratch integrity failure")
	}
	return nil
}

func (s *scratchDirectory) ReadFile(name string) ([]byte, error) {
	if s == nil || s.child < 0 || !validScratchPath(name) {
		return nil, errors.New("renderref: unsafe rendered path")
	}
	parts := strings.Split(name, "/")
	fd, err := unix.Dup(s.child)
	if err != nil {
		return nil, errors.New("renderref: output unavailable")
	}
	defer unix.Close(fd)
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, errors.New("renderref: output unavailable")
		}
		fd = next
	}
	file, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("renderref: output unavailable")
	}
	f := os.NewFile(uintptr(file), "output")
	data, readErr := io.ReadAll(io.LimitReader(f, 64<<20+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) > 64<<20 {
		return nil, errors.New("renderref: output unavailable")
	}
	return data, nil
}

func (s *scratchDirectory) Close() error {
	if s == nil || s.child < 0 || s.parent < 0 {
		return nil
	}
	err := removeChildren(s.child)
	if err == nil {
		err = unix.Unlinkat(s.parent, s.name, unix.AT_REMOVEDIR)
	}
	closeErr := errors.Join(s.childFile.Close(), s.parentFile.Close())
	s.child, s.parent = -1, -1
	return errors.Join(err, closeErr)
}

func removeChildren(fd int) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "scratch")
	entries, err := dir.ReadDir(-1)
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		name := entry.Name()
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			err = removeChildren(child)
			closeErr = unix.Close(child)
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
		} else if err := unix.Unlinkat(fd, name, 0); err != nil {
			return err
		}
	}
	return nil
}

func validScratchPath(name string) bool {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func identity(stat unix.Stat_t) scratchIdentity {
	return scratchIdentity{dev: uint64(stat.Dev), ino: uint64(stat.Ino), uid: stat.Uid, mode: uint32(stat.Mode)}
}
