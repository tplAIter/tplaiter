package gen

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ResolveParams resolves generator g's declared parameters from raw CLI-flag
// values. provided contains only EXPLICITLY supplied flags (name → string
// value); an absent key means the flag was not set and Default is used.
//
// Returns a name-to-value map (value type follows Param.Type: string→string,
// bool→bool, int→int, fields→[]Field) and parsed fields from a fields parameter
// (for convenient access as Context.Fields). Errors include a required
// parameter without a value or default and invalid values (int,
// fields).
func ResolveParams(g *manifest.Generator, provided map[string]string) (map[string]any, []Field, error) {
	params := make(map[string]any, len(g.Params))
	var fields []Field

	for i := range g.Params {
		p := &g.Params[i]
		raw, ok := provided[p.Name]
		if !ok {
			if p.Required && p.Default == nil {
				return nil, nil, requiredParamErr(p)
			}
			val, fs, err := defaultParamValue(p)
			if err != nil {
				return nil, nil, fmt.Errorf("parameter --%s (default): %w", p.Name, err)
			}
			params[p.Name] = val
			if p.Default != nil {
				if err := validateParamPattern(p, defaultRawValue(p)); err != nil {
					return nil, nil, fmt.Errorf("parameter --%s (default): %w", p.Name, err)
				}
			}
			if p.Type == manifest.ParamTypeFields {
				fields = fs
			}
			continue
		}
		if err := validateParamPattern(p, raw); err != nil {
			return nil, nil, fmt.Errorf("parameter --%s: %w", p.Name, err)
		}
		val, fs, err := convertParam(p, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parameter --%s: %w", p.Name, err)
		}
		params[p.Name] = val
		if p.Type == manifest.ParamTypeFields {
			fields = fs
		}
	}
	return params, fields, nil
}

// validateParamPattern checks a raw value before type conversion. This is the
// sole runtime-validation point for Param: single CLI gen, batch, and MCP all
// call ResolveParams first, so file writes do not begin before rejecting an
// invalid value.
func validateParamPattern(p *manifest.Param, raw string) error {
	if p.Pattern == "" {
		return nil
	}
	re, err := regexp.Compile(p.Pattern)
	if err != nil {
		// The normal path rejects this through manifest.Validate; this branch
		// protects library calls with a manually assembled manifest.
		return fmt.Errorf("invalid pattern %q: %w", p.Pattern, err)
	}
	if !re.MatchString(raw) {
		return fmt.Errorf("value %q does not match pattern %q", raw, p.Pattern)
	}
	return nil
}

func defaultRawValue(p *manifest.Param) string {
	switch v := p.Default.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	default:
		// defaultParamValue returns a more precise type-mismatch error.
		return ""
	}
}

func requiredParamErr(p *manifest.Param) error {
	if p.Description != "" {
		return fmt.Errorf("parameter --%s is required — %s", p.Name, p.Description)
	}
	return fmt.Errorf("parameter --%s is required", p.Name)
}

// convertParam converts a flag string to a typed value according to Param.Type
// (for fields, it also returns []Field).
func convertParam(p *manifest.Param, raw string) (any, []Field, error) {
	switch p.Type {
	case manifest.ParamTypeString:
		return raw, nil, nil
	case manifest.ParamTypeBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("expected bool, got %q", raw)
		}
		return b, nil, nil
	case manifest.ParamTypeInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("expected int, got %q", raw)
		}
		return n, nil, nil
	case manifest.ParamTypeFields:
		fs, err := ParseFields(raw)
		if err != nil {
			return nil, nil, err
		}
		return fs, fs, nil
	case manifest.ParamTypeList:
		return ParseList(raw), nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown parameter type %q", p.Type)
	}
}

// ParseList parses a comma-separated list "a,b,c" into []string. Elements are
// trimmed; empty elements (for example, from a trailing comma) are discarded.
// An empty/whitespace string returns nil, a valid "list not set" value.
func ParseList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if item := strings.TrimSpace(p); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// defaultParamValue builds a parameter value from Param.Default (or the type's
// zero value when Default is not set).
func defaultParamValue(p *manifest.Param) (any, []Field, error) {
	switch p.Type {
	case manifest.ParamTypeString:
		if p.Default == nil {
			return "", nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default must be a string")
		}
		return s, nil, nil
	case manifest.ParamTypeBool:
		if p.Default == nil {
			return false, nil, nil
		}
		b, ok := p.Default.(bool)
		if !ok {
			return nil, nil, errors.New("default must be bool")
		}
		return b, nil, nil
	case manifest.ParamTypeInt:
		if p.Default == nil {
			return 0, nil, nil
		}
		n, ok := p.Default.(int)
		if !ok {
			return nil, nil, errors.New("default must be int")
		}
		return n, nil, nil
	case manifest.ParamTypeFields:
		if p.Default == nil {
			return []Field(nil), nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default must be a string of the form name:type")
		}
		fs, err := ParseFields(s)
		if err != nil {
			return nil, nil, err
		}
		return fs, fs, nil
	case manifest.ParamTypeList:
		if p.Default == nil {
			return []string(nil), nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default must be a string of the form a,b,c")
		}
		return ParseList(s), nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown parameter type %q", p.Type)
	}
}

// DefaultFor returns Param.Default as a string for registering the default in a
// pflag.FlagSet (cmd/gen.go). For fields/string it is the string itself; for
// bool/int their string form; nil → "".
func DefaultFor(p *manifest.Param) string {
	if p.Default == nil {
		return ""
	}
	switch v := p.Default.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
