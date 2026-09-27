package update

import (
	"context"
	"errors"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// ErrLifecycleUnavailable reports that live update mutation has no T5
// lifecycle consumer. It intentionally reveals no source, path, or runtime
// detail.
var ErrLifecycleUnavailable = errors.New("TRUST_LIFECYCLE_UNAVAILABLE")

// Prepare verifies and previews a source/target update through the fixed
// authenticated runtime. It accepts no project path, manager, runner, permit,
// or caller-provided prepared authority and performs no publication or apply.
func Prepare(ctx context.Context, runtime *trustload.Runtime, input operationtrust.PrepareUpdateInput) (*operationtrust.PreparedUpdate, error) {
	return operationtrust.PrepareUpdate(ctx, runtime, input)
}
