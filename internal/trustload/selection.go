package trustload

import "context"

// ResolveProjectContext authenticates all installation documents before exact
// finite lookup. The key is a locator, not authority to construct a context.
func ResolveProjectContext(ctx context.Context, selection LaunchSelection, key string) (ProjectContext, error) {
	loaded, err := Load(ctx, selection)
	if err != nil {
		return ProjectContext{}, err
	}
	project, ok := selectedProjectContext(loaded.Install, key)
	if !ok {
		return ProjectContext{}, ErrProvenanceUnavailable
	}
	return project, nil
}
