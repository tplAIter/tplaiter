//go:build !darwin

package execx

import (
	"context"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func executeProjectBuild(context.Context, string, trustverify.StagedMaterial, *trustload.GoToolchain) (ProjectProcessResult, error) {
	return ProjectProcessResult{}, &ExecutionError{"TRUST_EXECUTION_UNAVAILABLE"}
}
