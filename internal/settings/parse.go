package settings

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ParseSet parses one CLI value in the form "group=value" (--set flag), typing it
// according to the manifest:
//   - select: value must be the id of an existing selectable, non-planned option;
//   - multiselect: "a,b,c" → []string, each item is a valid option;
//   - toggle: true/false/yes/no/1/0/on/off → bool;
//   - int: an integer;
//   - string: unchanged.
//
// It returns the group id and typed value. Errors list permitted values (the
// option list for select/multiselect).
func ParseSet(tpl *manifest.Template, expr string) (group string, value any, err error) {
	eq := strings.IndexByte(expr, '=')
	if eq < 0 {
		return "", nil, fmt.Errorf("value %q not in group=value format", expr)
	}
	group = strings.TrimSpace(expr[:eq])
	raw := strings.TrimSpace(expr[eq+1:])
	if group == "" {
		return "", nil, fmt.Errorf("value %q missing group name", expr)
	}

	idx := indexGroups(tpl)
	m, ok := idx[group]
	if !ok {
		return "", nil, fmt.Errorf("unknown group %q", group)
	}

	value, err = typeString(m.g, raw)
	if err != nil {
		return "", nil, fmt.Errorf("group %q: %w", group, err)
	}
	return group, value, nil
}

// LoadAnswersFile reads a YAML answers file (--answers) and types each value using
// the same manifest logic as other input. Raw scalar values (bool/int/string) and
// lists are converted to canonical group types. Unknown groups in the file are
// an error and all are listed.
func LoadAnswersFile(tpl *manifest.Template, path string) (Values, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading answers file %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing answers file %s: %w", path, err)
	}
	return typeAnswers(tpl, raw)
}

// typeAnswers types a raw answer map according to the manifest. It is separate to
// enable testing without the file system.
func typeAnswers(tpl *manifest.Template, raw map[string]any) (Values, error) {
	idx := indexGroups(tpl)
	out := make(Values, len(raw))

	// Deterministic traversal order produces stable error messages.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var unknown []string
	for _, k := range keys {
		m, ok := idx[k]
		if !ok {
			unknown = append(unknown, k)
			continue
		}
		val, err := typeNative(m.g, raw[k])
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", k, err)
		}
		out[k] = val
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown groups in answers file: %s", strings.Join(unknown, ", "))
	}
	return out, nil
}

// typeString types string input (--set) by group type.
func typeString(g *manifest.SettingGroup, raw string) (any, error) {
	switch g.Type {
	case manifest.TypeSelect:
		if err := checkOption(g, raw); err != nil {
			return nil, err
		}
		return raw, nil
	case manifest.TypeMultiselect:
		var out []string
		if raw != "" {
			for _, part := range strings.Split(raw, ",") {
				val := strings.TrimSpace(part)
				if val == "" {
					continue
				}
				if err := checkOption(g, val); err != nil {
					return nil, err
				}
				out = append(out, val)
			}
		}
		if out == nil {
			out = []string{}
		}
		return out, nil
	case manifest.TypeToggle:
		b, err := parseBool(raw)
		if err != nil {
			return nil, err
		}
		return b, nil
	case manifest.TypeInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("value %q is not an integer", raw)
		}
		return n, nil
	default: // string
		return raw, nil
	}
}

// typeNative types a native yaml value by group type. String forms (such as
// "true" for toggle) are allowed and delegated to typeString.
func typeNative(g *manifest.SettingGroup, raw any) (any, error) {
	switch g.Type {
	case manifest.TypeSelect:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected string (option id), got %T", raw)
		}
		if err := checkOption(g, s); err != nil {
			return nil, err
		}
		return s, nil
	case manifest.TypeMultiselect:
		if s, ok := raw.(string); ok {
			return typeString(g, s)
		}
		list := toStringSlice(raw)
		for _, val := range list {
			if err := checkOption(g, val); err != nil {
				return nil, err
			}
		}
		return list, nil
	case manifest.TypeToggle:
		switch b := raw.(type) {
		case bool:
			return b, nil
		case string:
			return parseBool(b)
		default:
			return nil, fmt.Errorf("expected bool, got %T", raw)
		}
	case manifest.TypeInt:
		if n, ok := toInt(raw); ok {
			return n, nil
		}
		if s, ok := raw.(string); ok {
			return typeString(g, s)
		}
		return nil, fmt.Errorf("expected integer, got %T", raw)
	default: // string
		if s, ok := raw.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", raw), nil
	}
}

// checkOption verifies that value is an existing selectable, non-planned group
// option. An error lists permitted non-planned values.
func checkOption(g *manifest.SettingGroup, value string) error {
	allowed := make([]string, 0, len(g.Options))
	for i := range g.Options {
		opt := &g.Options[i]
		if opt.Status == manifest.StatusPlanned {
			if opt.ID == value {
				return fmt.Errorf("option %q marked planned and unavailable for selection", value)
			}
			continue
		}
		allowed = append(allowed, opt.ID)
		if opt.ID == value {
			return nil
		}
	}
	return fmt.Errorf("invalid value %q, allowed: %s", value, strings.Join(allowed, ", "))
}

// parseBool parses CLI boolean input in a broad set of forms.
func parseBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "y", "on", "1":
		return true, nil
	case "false", "no", "n", "off", "0":
		return false, nil
	default:
		return false, fmt.Errorf("value %q not boolean (true/false/yes/no/on/off/1/0)", raw)
	}
}
