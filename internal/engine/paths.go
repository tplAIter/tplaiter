package engine

import (
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ifPrefix/ifSuffix wrap a conditional path segment.
const (
	ifPrefix = "__if_"
	ifSuffix = "__"
)

// evalIfSegment recognizes a conditional path segment and evaluates it against
// values. There are two forms:
//
//   - __if_<group>__ — type-specific default truth: toggle=true, select has a
//     non-empty group value (a non-empty value is not the same as selecting a
//     non-special option; a select with a non-zero default such as "none" is
//     always true), multiselect is non-empty, and int is not 0.
//   - __if_<group>=<value>__ — an exact `group=value` atom check
//     ([manifest.ParseCondition] + [settings.Eval]), supported for every group
//     type (for multiselect, it means “contains”).
//
// ok=false means the segment is not conditional (an ordinary directory/file
// name), so active and err have no meaning. err != nil means the segment is
// conditional but references an unknown group or is syntactically invalid;
// this is a manifest authoring error that aborts rendering.
func evalIfSegment(seg string, values settings.Values) (active, ok bool, err error) {
	if !strings.HasPrefix(seg, ifPrefix) || !strings.HasSuffix(seg, ifSuffix) {
		return false, false, nil
	}
	inner := seg[len(ifPrefix) : len(seg)-len(ifSuffix)]
	if inner == "" {
		return false, false, nil
	}

	if idx := strings.Index(inner, manifest.OpEq); idx >= 0 {
		group, value := inner[:idx], inner[idx+1:]
		if group == "" || value == "" {
			return false, true, fmt.Errorf("invalid conditional path segment %q", seg)
		}
		cond, err := manifest.ParseCondition(group + manifest.OpEq + value)
		if err != nil {
			return false, true, fmt.Errorf("conditional path segment %q: %w", seg, err)
		}
		active, err = settings.Eval(cond, values)
		if err != nil {
			return false, true, fmt.Errorf("conditional path segment %q: %w", seg, err)
		}
		return active, true, nil
	}

	raw, exists := values[inner]
	if !exists {
		return false, true, fmt.Errorf("conditional path segment %q references unknown group %q", seg, inner)
	}
	return truthy(raw), true, nil
}

// truthy determines the type-independent truthiness of a settings-group value:
// bool is used as-is, string and []string are true when non-empty, and int is
// true when non-zero. Any other type (including a missing value) is false.
func truthy(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val != ""
	case []string:
		return len(val) > 0
	case int:
		return val != 0
	default:
		return false
	}
}

// transformPath applies conditional segments __if_<group>__/__if_<group>=<value>__
// and substitutes name placeholders (__slug__, __module__, carried over from
// go-template unchanged). It returns (path, include?, error).
func (r *renderer) transformPath(rel string) (string, bool, error) {
	segs := strings.Split(rel, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		active, isIf, err := evalIfSegment(seg, r.values)
		if err != nil {
			return "", false, fmt.Errorf("engine: %s: %w", rel, err)
		}
		if isIf {
			if !active {
				return "", false, nil
			}
			continue
		}
		seg = strings.ReplaceAll(seg, "__slug__", r.ctx.Project.Slug)
		seg = strings.ReplaceAll(seg, "__module__", r.ctx.Project.Module)
		out = append(out, seg)
	}
	return strings.Join(out, "/"), true, nil
}
