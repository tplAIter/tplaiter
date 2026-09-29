//go:build darwin || linux

package mcpsrv

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const maxChildBinary = 64 << 20

type heldStage struct {
	root      string
	dir, file *os.File
	sum       [sha256.Size]byte
	mu        sync.Mutex
	dead      bool
}

func newHeldStage(source, scratchRoot string) (*heldStage, error) {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || source == "/" {
		return nil, errTransportUnavailable
	}
	if !filepath.IsAbs(scratchRoot) || filepath.Clean(scratchRoot) != scratchRoot || scratchRoot == "/" {
		return nil, errTransportUnavailable
	}
	fd, err := openNoFollowFile(source)
	if err != nil {
		return nil, errTransportUnavailable
	}
	src := os.NewFile(uintptr(fd), "tplaiter-source")
	var sourceStat unix.Stat_t
	if unix.Fstat(fd, &sourceStat) != nil || sourceStat.Mode&unix.S_IFMT != unix.S_IFREG || sourceStat.Size <= 0 || sourceStat.Size > maxChildBinary {
		_ = src.Close()
		return nil, errTransportUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(src, maxChildBinary+1))
	_ = src.Close()
	if err != nil || len(raw) == 0 || len(raw) > maxChildBinary {
		return nil, errTransportUnavailable
	}
	scratchFD, err := openNoFollowDir(scratchRoot)
	if err != nil {
		return nil, errTransportUnavailable
	}
	scratch := os.NewFile(uintptr(scratchFD), "tplaiter-authenticated-scratch")
	if scratch == nil {
		_ = unix.Close(scratchFD)
		return nil, errTransportUnavailable
	}
	scratchPath, err := pathFromFD(scratchFD)
	_ = scratch.Close()
	if err != nil {
		return nil, errTransportUnavailable
	}
	root, err := os.MkdirTemp(scratchPath, "tplaiter-held-stage-")
	if err != nil {
		return nil, errTransportUnavailable
	}
	fail := func() (*heldStage, error) { _ = os.RemoveAll(root); return nil, errTransportUnavailable }
	dir, err := os.Open(root)
	if err != nil {
		return fail()
	}
	if heldRoot, e := pathFromFD(int(dir.Fd())); e == nil {
		root = heldRoot
	}
	stage := filepath.Join(root, "tplaiter")
	out, err := unix.Open(stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o500)
	if err != nil {
		_ = dir.Close()
		return fail()
	}
	for rest := raw; len(rest) != 0; {
		n, e := unix.Write(out, rest)
		if e != nil || n <= 0 {
			_ = unix.Close(out)
			_ = dir.Close()
			return fail()
		}
		rest = rest[n:]
	}
	syncErr := unix.Fsync(out)
	closeErr := unix.Close(out)
	if syncErr != nil || closeErr != nil {
		_ = dir.Close()
		return fail()
	}
	verify, err := unix.Open(stage, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = dir.Close()
		return fail()
	}
	file := os.NewFile(uintptr(verify), "tplaiter-held-stage")
	got, err := io.ReadAll(io.LimitReader(file, maxChildBinary+1))
	if err != nil || len(got) != len(raw) || sha256.Sum256(got) != sha256.Sum256(raw) {
		_ = file.Close()
		_ = dir.Close()
		return fail()
	}
	return &heldStage{root: root, dir: dir, file: file, sum: sha256.Sum256(raw)}, nil
}

func (s *heldStage) launchPath() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead || s.file == nil || s.dir == nil {
		return "", errTransportUnavailable
	}
	var st unix.Stat_t
	if unix.Fstat(int(s.file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > maxChildBinary {
		return "", errTransportUnavailable
	}
	path, err := pathFromFD(int(s.file.Fd()))
	if err != nil || filepath.Dir(path) != s.root {
		return "", errTransportUnavailable
	}
	// The launch path must still name the exact held inode: a same-named
	// replacement or a symlink planted in the private directory is refused.
	var entry unix.Stat_t
	if unix.Lstat(path, &entry) != nil || entry.Mode&unix.S_IFMT != unix.S_IFREG || entry.Dev != st.Dev || entry.Ino != st.Ino {
		return "", errTransportUnavailable
	}
	if _, err = s.file.Seek(0, 0); err != nil {
		return "", errTransportUnavailable
	}
	got, err := io.ReadAll(io.LimitReader(s.file, maxChildBinary+1))
	if err != nil || sha256.Sum256(got) != s.sum {
		return "", errTransportUnavailable
	}
	return path, nil
}

func (s *heldStage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return nil
	}
	s.dead = true
	var err error
	if s.file != nil {
		err = s.file.Close()
	}
	if s.dir != nil {
		_ = s.dir.Close()
	}
	if e := os.RemoveAll(s.root); err == nil { //nolint:gosec // G703: root is the private MkdirTemp stage directory resolved from its held descriptor, never caller input
		err = e
	}
	return err
}

func stageChildExecutable(_ interface{}, source string) (string, func(), error) {
	s, err := newHeldStage(source, filepath.Dir(source))
	if err != nil {
		return "", func() {}, err
	}
	p, err := s.launchPath()
	if err != nil {
		_ = s.Close()
		return "", func() {}, err
	}
	return p, func() { _ = s.Close() }, nil
}

func openNoFollowDir(path string) (int, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return -1, errors.New("invalid path")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func openNoFollowFile(path string) (int, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return -1, errors.New("invalid path")
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, e := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
