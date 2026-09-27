//go:build !darwin

package execx

import (
	"context"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func executeApproved(context.Context, string, trustverify.StagedMaterial) ([]byte, error) {
	return nil, &ExecutionError{"TRUST_EXECUTION_UNAVAILABLE"}
}
