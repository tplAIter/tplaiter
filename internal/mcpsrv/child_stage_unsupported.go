//go:build !darwin && !linux

package mcpsrv

import "context"

// heldStage is the placeholder for the held child-executable copy on hosts
// other than Darwin and Linux.
// Hosts without a verified held-stage transport report errTransportUnavailable
// (surfaced to clients as MCP_UNAVAILABLE) instead of failing to compile.
type heldStage struct{}

func (*heldStage) launchPath() (string, error) { return "", errTransportUnavailable }

func (*heldStage) Close() error { return nil }

// stageChildExecutable keeps unsupported hosts explicit while preserving the
// existing lower-level transport tests. Darwin and Linux use the held-copy
// implementation in child_stage_unix.go.
func stageChildExecutable(context.Context, string) (string, func(), error) {
	return "", func() {}, errTransportUnavailable
}

func newHeldStage(string, string) (*heldStage, error) { return nil, errTransportUnavailable }
