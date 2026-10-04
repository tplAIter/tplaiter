//go:build darwin || linux

package execx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const liveMkdirChildArg = "--tplaiter-internal-mkdir-at-fd"

// This is a native filesystem primitive, not a template command runner. The
// isolated copy of this executable receives only a held parent directory FD
// and one basename. It has no path/root/profile override, environment, shell,
// network or signing interface. Setting the child umask cannot affect the
// invoking CLI/MCP process or other tests. No directory chmod is performed.
func init() {
	if len(os.Args) < 2 || os.Args[1] != liveMkdirChildArg {
		return
	}
	if len(os.Args) != 3 || !liveMkdirBasename(os.Args[2]) {
		os.Exit(1)
	}
	parent := os.NewFile(3, "live-new-parent")
	if parent == nil {
		os.Exit(1)
	}
	info, err := parent.Stat()
	if err != nil || !info.IsDir() {
		os.Exit(1)
	}
	unix.Umask(0) // confined to this short-lived helper process
	if err := unix.Mkdirat(3, os.Args[2], 0o755); err != nil {
		os.Exit(1)
	}
	if err := parent.Sync(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func liveMkdirBasename(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00\r\n")
}

// MkdirAtParent creates one directory using a held, identity-checked parent FD.
// The only executable is this process's own fixed native helper; it inherits no
// environment and changes umask only in the child. Completion is bounded.
func MkdirAtParent(ctx context.Context, parent *os.File, expected os.FileInfo, base string) error {
	if ctx == nil || parent == nil || expected == nil || !liveMkdirBasename(base) {
		return errors.New("invalid native mkdir input")
	}
	opened, err := parent.Stat()
	if err != nil {
		return err
	}
	if !opened.IsDir() || !os.SameFile(expected, opened) {
		return errors.New("native mkdir parent identity mismatch")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	child := exec.CommandContext(childCtx, executable, liveMkdirChildArg, base)
	child.Env = []string{}
	child.ExtraFiles = []*os.File{parent}
	if err := child.Run(); err != nil {
		return errors.Join(err, childCtx.Err())
	}
	return nil
}
