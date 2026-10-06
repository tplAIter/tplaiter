//go:build !darwin && !linux

package execx

import (
	"context"
	"os"
	"os/exec"
)

func actionReadFlags() int         { return os.O_RDONLY }
func actionControlNonblock() error { return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"} }
func prepareActionChild(*exec.Cmd) {}
func killActionChild(c *exec.Cmd) {
	if c.Process != nil {
		_ = c.Process.Kill()
	}
}
func actionProcessSignal(*os.ProcessState) int { return 0 }
func executeReadonlyAction(context.Context, string, actionLaunch) (ActionProcessResult, error) {
	return ActionProcessResult{}, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
}

func verifyActionInherited(actionLaunch) error {
	return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
}

func enterReadonlyAction(context.Context, actionLaunch) error {
	return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
}
