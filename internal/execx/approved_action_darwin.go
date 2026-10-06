//go:build darwin

package execx

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func actionReadFlags() int           { return os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK }
func actionControlNonblock() error   { return unix.SetNonblock(3, true) }
func prepareActionChild(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killActionChild(c *exec.Cmd) {
	if c.Process != nil {
		_ = unix.Kill(-c.Process.Pid, unix.SIGKILL)
		_ = c.Process.Kill()
	}
}

func actionProcessSignal(s *os.ProcessState) int {
	if x, ok := s.Sys().(syscall.WaitStatus); ok && x.Signaled() {
		return int(x.Signal())
	}
	return 0
}

// The actual Go bootstrap on the sampled Darwin host refuses installation of
// the approved 2 GiB RLIMIT_AS with EINVAL. This is not a claim that Darwin lacks
// RLIMIT_AS: current virtual usage can already exceed the proposed ceiling.
// A proved lower-footprint transition or explicit profile amendment is required
// before any signed native action can enter this backend.
func executeReadonlyAction(context.Context, string, actionLaunch) (ActionProcessResult, error) {
	return ActionProcessResult{}, &ExecutionError{"TRUST_ACTION_ADDRESS_BOUND_UNAVAILABLE"}
}

func verifyActionInherited(actionLaunch) error {
	return &ExecutionError{"TRUST_ACTION_ADDRESS_BOUND_UNAVAILABLE"}
}

func enterReadonlyAction(context.Context, actionLaunch) error {
	return &ExecutionError{"TRUST_ACTION_ADDRESS_BOUND_UNAVAILABLE"}
}
