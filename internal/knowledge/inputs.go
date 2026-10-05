package knowledge

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
)

const InputsAPIVersion = "tplaiter.dev/knowledge-inputs/v1"

// InputContract is descriptive context and input metadata, never invocation
// authority. ContextFloor is a closed list that a later selector must preserve.
type InputContract struct {
	APIVersion   string            `json:"apiVersion"`
	ContextFloor []string          `json:"contextFloor"`
	Definitions  []InputDefinition `json:"definitions"`
}

type InputDefinition struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	// Nil is absent. Literal JSON null and false remain present and distinct.
	Default     json.RawMessage  `json:"default,omitempty"`
	Constraints InputConstraints `json:"constraints"`
}

type InputConstraints struct {
	MinLength *int              `json:"minLength,omitempty"`
	MaxLength *int              `json:"maxLength,omitempty"`
	Pattern   *string           `json:"pattern,omitempty"`
	Minimum   *int64            `json:"minimum,omitempty"`
	Maximum   *int64            `json:"maximum,omitempty"`
	Enum      []json.RawMessage `json:"enum,omitempty"`
}

func versionEnvelope(raw []byte, dst *map[string]json.RawMessage) error {
	// Preflight validates exact Unicode, duplicate keys, depth and EOF while
	// permitting JSON null. Only nullable input defaults/enum values may contain null in v1.
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

func decodeDescriptor(raw []byte, dst *Catalog) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(root["items"], &items); err != nil {
		return err
	}
	for _, item := range items {
		var inputs map[string]json.RawMessage
		if v, ok := item["inputs"]; ok {
			if err := json.Unmarshal(v, &inputs); err != nil {
				return err
			}
			var definitions []map[string]json.RawMessage
			if err := json.Unmarshal(inputs["definitions"], &definitions); err != nil {
				return err
			}
			for _, definition := range definitions {
				if bytes.Equal(bytes.TrimSpace(definition["default"]), []byte("null")) {
					definition["default"] = json.RawMessage("false")
				}
				// Nullable enum alternatives are also scalar declarations, not globally
				// allowed null fields; replace them solely for the closed shape check.
				if v, ok := definition["constraints"]; ok {
					var constraints map[string]json.RawMessage
					if err := json.Unmarshal(v, &constraints); err != nil {
						return err
					}
					if v, ok := constraints["enum"]; ok {
						var values []json.RawMessage
						if err := json.Unmarshal(v, &values); err != nil {
							return err
						}
						for i, value := range values {
							if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
								values[i] = json.RawMessage("false")
							}
						}
						if values != nil {
							b, err := json.Marshal(values)
							if err != nil {
								return err
							}
							constraints["enum"] = b
						}
					}
					b, err := json.Marshal(constraints)
					if err != nil {
						return err
					}
					definition["constraints"] = b
				}
			}
			if definitions != nil {
				b, err := json.Marshal(definitions)
				if err != nil {
					return err
				}
				inputs["definitions"] = b
			}
			b, err := json.Marshal(inputs)
			if err != nil {
				return err
			}
			item["inputs"] = b
		}
	}
	if items != nil {
		b, err := json.Marshal(items)
		if err != nil {
			return err
		}
		root["items"] = b
	}
	shaped, err := json.Marshal(root)
	if err != nil {
		return err
	}
	if err := canonicaljson.DecodeStrict(shaped, dst); err != nil {
		return err
	}
	// Recover original scalar lexemes and literal null defaults after closed
	// shape validation, so source/export number rules are not normalized away.
	return json.Unmarshal(raw, dst)
}

func validateInputs(in InputContract, path string) error {
	if in.APIVersion != InputsAPIVersion {
		return fail(UnsupportedVersion, path+".inputs.apiVersion")
	}
	if in.ContextFloor == nil || len(in.ContextFloor) > 16 || in.Definitions == nil || len(in.Definitions) > 16 {
		return fail(Invalid, path+".inputs")
	}
	names := map[string]bool{}
	for _, d := range in.Definitions {
		if !tokenRE.MatchString(d.Name) || names[d.Name] || !oneOf(d.Type, "string", "integer", "boolean") {
			return fail(Invalid, path+".inputs.definition")
		}
		names[d.Name] = true
		c := d.Constraints
		if (c.MinLength != nil && (*c.MinLength < 0 || *c.MinLength > 4096)) || (c.MaxLength != nil && (*c.MaxLength < 0 || *c.MaxLength > 4096)) || (c.MinLength != nil && c.MaxLength != nil && *c.MinLength > *c.MaxLength) {
			return fail(Invalid, path+".inputs.length")
		}
		if d.Type != "string" && (c.MinLength != nil || c.MaxLength != nil || c.Pattern != nil) {
			return fail(Invalid, path+".inputs.string constraints")
		}
		if c.Pattern != nil && len(*c.Pattern) > 256 {
			return fail(Invalid, path+".inputs.pattern")
		}
		if c.Pattern != nil {
			if _, err := regexp.Compile(*c.Pattern); err != nil {
				return fail(Invalid, path+".inputs.pattern")
			}
		}
		if d.Type != "integer" && (c.Minimum != nil || c.Maximum != nil) {
			return fail(Invalid, path+".inputs.integer constraints")
		}
		if (c.Minimum != nil && (*c.Minimum < -9007199254740991 || *c.Minimum > 9007199254740991)) || (c.Maximum != nil && (*c.Maximum < -9007199254740991 || *c.Maximum > 9007199254740991)) || (c.Minimum != nil && c.Maximum != nil && *c.Minimum > *c.Maximum) {
			return fail(Invalid, path+".inputs.range")
		}
		if c.Enum != nil && len(c.Enum) == 0 || len(c.Enum) > 16 {
			return fail(Invalid, path+".inputs.enum")
		}
		choices := map[string]bool{}
		for _, v := range c.Enum {
			if !inputValue(d, v) {
				return fail(Invalid, path+".inputs.enum")
			}
			key, err := canonicaljson.Canonicalize(v)
			if err != nil || choices[string(key)] {
				return fail(AmbiguousID, path+".inputs.enum")
			}
			choices[string(key)] = true
		}
		if d.Default != nil {
			if !inputValue(d, d.Default) {
				return fail(Invalid, path+".inputs.default")
			}
			if c.Enum != nil {
				key, err := canonicaljson.Canonicalize(d.Default)
				if err != nil || !choices[string(key)] {
					return fail(Invalid, path+".inputs.default enum")
				}
			}
		}
	}
	return nil
}

func inputValue(d InputDefinition, raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4096 {
		return false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return d.Nullable
	}
	if deps.ValidateScalarParameter(raw) != nil {
		return false
	}
	c := d.Constraints
	switch d.Type {
	case "string":
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return false
		}
		n := utf8.RuneCountInString(v)
		if c.MinLength != nil && n < *c.MinLength || c.MaxLength != nil && n > *c.MaxLength {
			return false
		}
		if c.Pattern == nil {
			return true
		}
		matched, err := regexp.MatchString(*c.Pattern, v)
		return err == nil && matched
	case "integer":
		v, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
		return err == nil && (c.Minimum == nil || v >= *c.Minimum) && (c.Maximum == nil || v <= *c.Maximum)
	case "boolean":
		var v bool
		return json.Unmarshal(raw, &v) == nil
	default:
		return false
	}
}
