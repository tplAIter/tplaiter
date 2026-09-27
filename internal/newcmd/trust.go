package newcmd

import (
	"context"
	"errors"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// ErrLifecycleUnavailable reports that live project creation has no T5
// lifecycle consumer. It is a safe, stable diagnostic and carries no source,
// path, policy, or runtime detail.
var ErrLifecycleUnavailable = errors.New("TRUST_LIFECYCLE_UNAVAILABLE")

// Prepare verifies and previews a new project from an authenticated fixed
// runtime. The input is only D's bounded untrusted source selection and render
// values; it cannot supply a path, manager, runner, permit, or prepared
// outcome. This method neither creates nor publishes a project.
func Prepare(ctx context.Context, runtime *trustload.Runtime, input operationtrust.PrepareNewInput) (*operationtrust.PreparedNew, error) {
	return operationtrust.PrepareNew(ctx, runtime, input)
}
