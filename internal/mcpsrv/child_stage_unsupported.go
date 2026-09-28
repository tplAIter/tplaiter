//go:build !darwin

package mcpsrv

import "context"

// stageChildExecutable keeps unsupported hosts explicit while preserving the
// existing lower-level transport tests. Production Darwin uses the held-copy
// implementation in child_stage_darwin.go.
func stageChildExecutable(context.Context, string) (string, func(), error) {
	return "", func() {}, errTransportUnavailable
}

func newHeldStage(string, string) (*heldStage, error) { return nil, errTransportUnavailable }
