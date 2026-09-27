// Package settings implements the template settings value model and resolver:
// typed group values, evaluation of the [manifest.Condition] mini-language, CLI
// value parsing (--set/--answers), transitive requires resolution with implication
// and conflict/cycle detection, constraint validation, and rendering context
// construction with Is/Has helpers.
//
// The package builds on [manifest]: it takes group tree structures and condition
// syntax from there, while all evaluation semantics live here. [manifest] does
// not import settings and is unchanged by this implementation.
package settings

import (
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Values is a settings value set: group id → value according to the group type.
// The value type is canonical: string for select/string, []string for
// multiselect, bool for toggle, and int for int. Values are stored flat by group
// id (the manifest validator guarantees global uniqueness, including nested ids).
type Values map[string]any

// Clone returns a shallow copy of values, copying []string slices so mutations of
// a derived set do not leak into the original.
func (v Values) Clone() Values {
	out := make(Values, len(v))
	for k, val := range v {
		if list, ok := val.([]string); ok {
			cp := make([]string, len(list))
			copy(cp, list)
			out[k] = cp
			continue
		}
		out[k] = val
	}
	return out
}

// groupMeta contains a group and its activating parent for tree traversal.
// parentGroup == "" means a root group (always active). Otherwise the group is
// active when parentOpt is selected in parentGroup (and parentGroup is active).
type groupMeta struct {
	g           *manifest.SettingGroup
	parentGroup string
	parentOpt   string
}

// optionMeta is a select/multiselect option with a back-reference to its group.
type optionMeta struct {
	opt   *manifest.Option
	group string
}

// indexGroups builds a flat group id → metadata map (type, default, parent) by
// traversing the entire settings tree, including nested refinements.
func indexGroups(tpl *manifest.Template) map[string]groupMeta {
	idx := make(map[string]groupMeta)
	var walk func(groups []manifest.SettingGroup, parentGroup, parentOpt string)
	walk = func(groups []manifest.SettingGroup, parentGroup, parentOpt string) {
		for i := range groups {
			g := &groups[i]
			if _, dup := idx[g.Group]; !dup {
				idx[g.Group] = groupMeta{g: g, parentGroup: parentGroup, parentOpt: parentOpt}
			}
			for j := range g.Options {
				opt := &g.Options[j]
				walk(opt.Settings, g.Group, opt.ID)
			}
		}
	}
	walk(tpl.Settings, "", "")
	return idx
}

// indexOptions builds a "group=optionID" → option map for select/multiselect
// groups. The key matches the canonical condition atom form (§3.2), allowing
// requires atoms to be linked directly to options.
func indexOptions(tpl *manifest.Template) map[string]optionMeta {
	idx := make(map[string]optionMeta)
	var walk func(groups []manifest.SettingGroup)
	walk = func(groups []manifest.SettingGroup) {
		for i := range groups {
			g := &groups[i]
			for j := range g.Options {
				opt := &g.Options[j]
				if g.Type == manifest.TypeSelect || g.Type == manifest.TypeMultiselect {
					key := g.Group + manifest.OpEq + opt.ID
					if _, dup := idx[key]; !dup {
						idx[key] = optionMeta{opt: opt, group: g.Group}
					}
				}
				walk(opt.Settings)
			}
		}
	}
	walk(tpl.Settings)
	return idx
}

// DefaultValues returns defaults for ALL groups in the tree, including nested
// refinements. Nested-group defaults always apply; activity (the parent selection)
// is separately calculated in [Resolve] through ActiveValues.
func DefaultValues(tpl *manifest.Template) Values {
	v := make(Values)
	for id, m := range indexGroups(tpl) {
		v[id] = defaultFor(m.g)
	}
	return v
}

// defaultFor converts a group manifest default to its canonical Go type. Without
// a default, it returns the type's zero value.
func defaultFor(g *manifest.SettingGroup) any {
	if g.Default == nil {
		return zeroValue(g.Type)
	}
	switch g.Type {
	case manifest.TypeSelect:
		if s, ok := g.Default.(string); ok {
			return s
		}
	case manifest.TypeMultiselect:
		return toStringSlice(g.Default)
	case manifest.TypeToggle:
		if b, ok := g.Default.(bool); ok {
			return b
		}
	case manifest.TypeString:
		if s, ok := g.Default.(string); ok {
			return s
		}
	case manifest.TypeInt:
		if n, ok := toInt(g.Default); ok {
			return n
		}
	}
	return zeroValue(g.Type)
}

// zeroValue is the empty value for the canonical group type: "" for select/string,
// an empty []string for multiselect, false for toggle, and 0 for int.
func zeroValue(typ string) any {
	switch typ {
	case manifest.TypeMultiselect:
		return []string{}
	case manifest.TypeToggle:
		return false
	case manifest.TypeInt:
		return 0
	default: // select, string, and unknown types
		return ""
	}
}

// toStringSlice converts a yaml value (usually []any) to []string.
func toStringSlice(v any) []string {
	switch list := v.(type) {
	case []string:
		out := make([]string, len(list))
		copy(out, list)
		return out
	case []any:
		out := make([]string, 0, len(list))
		for _, el := range list {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

// toInt converts a numeric yaml value to int (int, int64, or float64 without a
// fractional part).
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// contains reports whether a slice contains a value.
func contains(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}
