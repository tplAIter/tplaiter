//go:build !darwin && !linux

package operationtrust

import (
	"context"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func captureProjectBuild(context.Context, string) ([]trustverify.ContentEntry, [][]byte, error) {
	return nil, nil, ErrProjectBuild
}
