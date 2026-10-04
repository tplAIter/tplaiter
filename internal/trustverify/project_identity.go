package trustverify

import (
	"context"
	"path/filepath"
)

// CheckProjectIdentity verifies untrusted observations of a project root and
// marker ID against this runtime's selected installation context. Expected
// identity is never supplied by the caller. Reloading all authority inputs
// proves that the constructor's project projection and profile remain current.
// An older reader without an installed root cannot vouch for stable state.
func (r *Runtime) CheckProjectIdentity(ctx context.Context, actualRoot, observedMarkerID string) error {
	binding, _, _, err := r.load(ctx)
	if err != nil {
		return err
	}
	if !binding.Equal(r.binding) || r.project.RootPath == "" || !filepath.IsAbs(r.project.RootPath) || filepath.Clean(r.project.RootPath) != r.project.RootPath || actualRoot != r.project.RootPath || observedMarkerID != r.project.ProjectID {
		return diagnostic(TrustRuntimeInvalid, nil)
	}
	return ctx.Err()
}
