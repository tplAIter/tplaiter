//go:build !darwin && !linux

package ossinstall

import (
	"context"
	"errors"
)

func writeExecutionCAS(context.Context, string, string, []byte) error {
	return errors.New("TRUST_EXECUTION_UNAVAILABLE")
}
