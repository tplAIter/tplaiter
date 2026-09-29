//go:build linux

package mcpsrv

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// pathFromFD resolves the current path of an open descriptor through the
// procfs magic link /proc/self/fd/<n>. The result is accepted only when it is
// an absolute, clean path to a live object: procfs appends " (deleted)" to an
// unlinked inode, and pseudo-files such as pipes resolve to "pipe:[...]"; both
// fail closed. A host without a mounted /proc cannot provide the held-stage
// transport and reports MCP_UNAVAILABLE.
func pathFromFD(fd int) (string, error) {
	if fd < 0 {
		return "", errors.New("invalid descriptor")
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlink("/proc/self/fd/"+strconv.Itoa(fd), buf)
	if err != nil {
		return "", err
	}
	if n <= 0 || n >= len(buf) {
		return "", errors.New("unresolvable descriptor path")
	}
	path := string(buf[:n])
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasSuffix(path, " (deleted)") {
		return "", errors.New("unresolvable descriptor path")
	}
	// The magic link must name the same inode the descriptor holds.
	var held, named unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Lstat(path, &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino {
		return "", errors.New("descriptor path does not match its inode")
	}
	return path, nil
}
