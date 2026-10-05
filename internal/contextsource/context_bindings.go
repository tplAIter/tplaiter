package contextsource

import (
	"io/fs"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
)

const ContextSourceBindingsAPIVersion = "tplaiter.dev/context-source-bindings/v2"
const ContextSourceBindingsPath = "catalog/context-source-bindings.v2.json"

type ContextCatalogBinding struct {
	Alias            string           `json:"alias"`
	ProviderID       string           `json:"providerID"`
	Parameters       []deps.Parameter `json:"parameters"`
	EntriesPath      string           `json:"entriesPath"`
	PayloadDirectory string           `json:"payloadDirectory"`
	ToolPath         string           `json:"toolPath"`
}

// An association is authored by the consumer source and must match the
// authenticated dependency's own declaration before it becomes graph data.
type ContextDependencyBinding struct {
	Alias      string           `json:"alias"`
	ProviderID string           `json:"providerID"`
	Parameters []deps.Parameter `json:"parameters"`
}
type ContextSourceBindings struct {
	APIVersion   string                     `json:"apiVersion"`
	Kind         string                     `json:"kind"`
	Source       ContextCatalogBinding      `json:"source"`
	Dependencies []ContextDependencyBinding `json:"dependencies"`
}

func contextResourcePath(p string) bool {
	return utf8.ValidString(p) && len(p) <= 256 && fs.ValidPath(p) && p != "." && !strings.ContainsAny(p, "\\\x00\r\n") && exports.ValidatePortablePath(p) == nil
}
func DecodeContextSourceBindingsV2(raw []byte) (ContextSourceBindings, error) {
	var b ContextSourceBindings
	if decodeContextWire(raw, &b, 64<<10) != nil || b.APIVersion != ContextSourceBindingsAPIVersion || b.Kind != "ContextSourceBindings" || len(b.Dependencies) > MaxContextSources-1 {
		return b, errContextSources
	}
	s := b.Source
	if !contextAliasRE.MatchString(s.Alias) || !contextProviderRE.MatchString(s.ProviderID) || contextParameters(s.Parameters) != nil || !contextResourcePath(s.EntriesPath) || !contextResourcePath(s.PayloadDirectory) || !contextResourcePath(s.ToolPath) || s.EntriesPath == s.ToolPath {
		return b, errContextSources
	}
	for i, d := range b.Dependencies {
		if !contextAliasRE.MatchString(d.Alias) || d.Alias == s.Alias || !contextProviderRE.MatchString(d.ProviderID) || contextParameters(d.Parameters) != nil || (i > 0 && b.Dependencies[i-1].Alias >= d.Alias) {
			return b, errContextSources
		}
	}
	return b, nil
}
