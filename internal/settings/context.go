package settings

import "github.com/tplAIter/tplaiter/internal/manifest"

// View is the render engine's view of active settings values. As a named
// map[string]any type it enables `.Settings.<group>` access in templates and
// provides Is/Has helper methods (§3.1). The engine (the  implementation) may
// also register them as `is`/`has` FuncMap functions.
type View map[string]any

// Is reports whether a group's value equals the requested value (equality for
// select/string, comparison with true/false for toggle, numeric comparison for
// int). Use [View.Has] for multiselect.
func (s View) Is(group, value string) bool {
	raw, ok := s[group]
	if !ok {
		return false
	}
	if _, isList := raw.([]string); isList {
		return false
	}
	return matchValue(raw, value)
}

// Has reports whether a multiselect group contains the requested value. It is
// always false for non-multiselect groups.
func (s View) Has(group, value string) bool {
	list, ok := s[group].([]string)
	if !ok {
		return false
	}
	return contains(list, value)
}

// RenderContext builds the render engine context from resolved settings:
// `.Settings` contains active values (a View with Is/Has helpers). The
// implementation adds project fields (Project/Name/…) and registers Is/Has in
// the FuncMap.
func RenderContext(_ *manifest.Template, resolved Resolved) map[string]any {
	return map[string]any{
		"Settings": View(resolved.ActiveValues),
	}
}
