package contextsource

import "github.com/tplAIter/tplaiter/internal/contextwire"

const ContextSourceBindingsAPIVersion = contextwire.ContextSourceBindingsAPIVersion
const ContextSourceBindingsPath = contextwire.ContextSourceBindingsPath

type ContextCatalogBinding = contextwire.ContextCatalogBinding
type ContextDependencyBinding = contextwire.ContextDependencyBinding
type ContextSourceBindings = contextwire.ContextSourceBindings

func contextResourcePath(p string) bool { return contextwire.ResourcePath(p) }
func DecodeContextSourceBindingsV2(raw []byte) (ContextSourceBindings, error) {
	return contextwire.DecodeContextSourceBindingsV2(raw)
}
