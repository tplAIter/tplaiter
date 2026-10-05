package trustload

import (
	"path/filepath"
	"regexp"
)

var workspaceServiceSlug = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// An authenticated parent link is the only permitted nested installed context.
// A workspace cannot itself be a linked service or transitively grant subroots.
func workspaceContextPair(a, b ProjectContext) bool {
	if a.WorkspaceContext == b.Key {
		a, b = b, a
	}
	if a.WorkspaceContext != "" || b.WorkspaceContext != a.Key || a.Key == b.Key {
		return false
	}
	rel, err := filepath.Rel(filepath.Join(a.RootPath, "services"), b.RootPath)
	return err == nil && workspaceServiceSlug.MatchString(rel) && filepath.Join(a.RootPath, "services", rel) == b.RootPath
}
