//go:build darwin || linux

package newcmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/newtransaction"
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

func mkdirLiveDirectory(root *os.Root, name string, expectedParent os.FileInfo) error {
	base := filepath.Base(name)
	if !liveMkdirBasename(base) || expectedParent == nil {
		return newtransaction.ErrOwnershipUncertain
	}
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer parent.Close()
	opened, err := parent.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(expectedParent, opened) {
		return newtransaction.ErrOwnershipUncertain
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(executable, liveMkdirChildArg, base)
	child.Env = []string{}
	child.ExtraFiles = []*os.File{parent}
	if err := child.Run(); err != nil {
		return errors.Join(newtransaction.ErrOwnershipUncertain, err)
	}
	return nil
}
