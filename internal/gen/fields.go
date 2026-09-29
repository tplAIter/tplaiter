package gen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
)

// Field — one entity field parsed from a `fields` parameter string
// (`"customer:string,amount:float64,tags:[]string"`). Available to snippets as
// a `.Fields` element: name in all cases (`.Name.Pascal`, etc.), Go type for
// structs/signatures, SQL type for migrations, and zero value for constructors.
type Field struct {
	// NameRaw — field name as written in the specification (before normalization).
	NameRaw string
	// Name — derived name variants (Pascal/Camel/Snake/Kebab), as in [Name].
	Name Name
	// GoType — field Go type (`string`, `int64`, `time.Time`, `uuid.UUID`, `[]string`).
	GoType string
	// IsSlice — true for slice types (`[]T`).
	IsSlice bool
	// Zero — zero-value literal for the Go type (`""`, `0`, `false`, `nil`, `time.Time{}`).
	Zero string
	// SQLType — column type for goose migrations (`text`, `bigint`, `jsonb`, ...).
	SQLType string
}

// fieldTypeInfo — entry in the supported field-type table.
type fieldTypeInfo struct {
	goType  string
	sqlType string
	zero    string
}

// fieldTypes — allowlist of scalar field types. The table is extensible by one
// line per type. Slices `[]T` are built from a scalar base type (see
// [parseFieldType]) and always map to jsonb.
var fieldTypes = map[string]fieldTypeInfo{
	"string":    {goType: "string", sqlType: "text", zero: `""`},
	"int":       {goType: "int", sqlType: "bigint", zero: "0"},
	"int64":     {goType: "int64", sqlType: "bigint", zero: "0"},
	"float64":   {goType: "float64", sqlType: "double precision", zero: "0"},
	"bool":      {goType: "bool", sqlType: "boolean", zero: "false"},
	"time.Time": {goType: "time.Time", sqlType: "timestamptz", zero: "time.Time{}"},
	"uuid":      {goType: "uuid.UUID", sqlType: "uuid", zero: "uuid.UUID{}"},
}

// ParseFields parses a field specification `"name:type,name:type,..."` into
// []Field. An empty string returns an empty result (not an error). Errors (with
// the allowed-type list) cover an empty element, missing ":", invalid name,
// unknown type, and duplicate name.
func ParseFields(spec string) ([]Field, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	out := make([]Field, 0, len(parts))
	seen := make(map[string]bool, len(parts))

	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, fmt.Errorf("fields %q: empty element (expected name:type)", spec)
		}
		name, typ, ok := strings.Cut(item, ":")
		name = strings.TrimSpace(name)
		typ = strings.TrimSpace(typ)
		if !ok || name == "" || typ == "" {
			return nil, fmt.Errorf("field %q: expected name:type", item)
		}

		n := Name{
			Raw:    name,
			Pascal: engine.Pascal(name),
			Camel:  engine.Camel(name),
			Snake:  engine.Snake(name),
			Kebab:  engine.Kebab(name),
		}
		if n.Pascal == "" || !identRe.MatchString(n.Snake) {
			return nil, fmt.Errorf("field %q: invalid name %q (derived snake %q must match %s)",
				item, name, n.Snake, identRe.String())
		}
		if seen[n.Snake] {
			return nil, fmt.Errorf("field %q: duplicate name %q", spec, name)
		}
		seen[n.Snake] = true

		goType, sqlType, zero, isSlice, typErr := parseFieldType(typ)
		if typErr != nil {
			return nil, fmt.Errorf("field %q: %w", item, typErr)
		}
		out = append(out, Field{
			NameRaw: name,
			Name:    n,
			GoType:  goType,
			IsSlice: isSlice,
			Zero:    zero,
			SQLType: sqlType,
		})
	}
	return out, nil
}

// parseFieldType resolves a field type: a scalar from [fieldTypes] or a `[]T`
// slice (base T is an allowlisted scalar; slice SQL type is jsonb, zero is nil).
func parseFieldType(typ string) (goType, sqlType, zero string, isSlice bool, err error) {
	if base, ok := strings.CutPrefix(typ, "[]"); ok {
		info, known := fieldTypes[base]
		if !known {
			return "", "", "", false, fmt.Errorf("unknown slice element type %q (allowed: %s)", base, allowedTypesList())
		}
		return "[]" + info.goType, "jsonb", "nil", true, nil
	}
	info, ok := fieldTypes[typ]
	if !ok {
		return "", "", "", false, fmt.Errorf("unknown type %q (allowed: %s)", typ, allowedTypesList())
	}
	return info.goType, info.sqlType, info.zero, false, nil
}

// allowedTypesList returns a sorted list of allowed base types (plus the []T
// form) for error messages.
func allowedTypesList() string {
	names := make([]string, 0, len(fieldTypes)+1)
	for t := range fieldTypes {
		names = append(names, t)
	}
	sort.Strings(names)
	names = append(names, "[]T")
	return strings.Join(names, ", ")
}
