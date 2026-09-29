package resultdto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// SchemaID is the $id of the published result/v1 JSON schema
// (schema/result.v1.schema.json).
const SchemaID = "https://tplaiter.dev/schema/result.v1.schema.json"

// GenerateSchema returns the published result/v1 JSON schema. It is derived
// from the operation registry, so the file in schema/ cannot drift from the
// Go contract (TestSchemaFileMatchesGenerator).
func GenerateSchema() ([]byte, error) {
	root := baseSchema(false)
	root["$id"] = SchemaID
	ops := Operations()
	operations := make([]any, 0, len(ops))
	kinds := make([]any, 0, len(ops))
	var globals, projects []any
	allOf := make([]any, 0, len(ops)+2)
	for _, op := range ops {
		spec := operationRegistry[op]
		operations = append(operations, string(op))
		kinds = append(kinds, spec.kind)
		switch spec.scope {
		case ScopeGlobal:
			globals = append(globals, string(op))
		case ScopeProject:
			projects = append(projects, string(op))
		case ScopeOptional:
		}
		allOf = append(allOf, map[string]any{
			"if":   map[string]any{"properties": map[string]any{"operation": map[string]any{"const": string(op)}}, "required": []any{"operation"}},
			"then": map[string]any{"properties": map[string]any{"kind": map[string]any{"const": spec.kind}}},
		})
	}
	props := root["properties"].(map[string]any)
	props["operation"] = map[string]any{"enum": operations}
	props["kind"] = map[string]any{"enum": sortedUnique(kinds)}
	allOf = append(
		allOf,
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"operation": map[string]any{"enum": globals}}, "required": []any{"operation"}},
			"then": map[string]any{"properties": map[string]any{"project": map[string]any{"type": "null"}}},
		},
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"operation": map[string]any{"enum": projects},
					"status":    map[string]any{"enum": []any{string(StatusOK), string(StatusChanges), string(StatusConflicted)}},
				},
				"required": []any{"operation", "status"},
			},
			"then": map[string]any{"properties": map[string]any{"project": map[string]any{"$ref": "#/$defs/project"}}},
		},
	)
	root["allOf"] = allOf
	return encodeSchema(root)
}

// OperationSchema returns a self-contained result/v1 schema for one
// operation: operation and kind are constants, the project rule of the
// operation's scope is resolved, and data is described by dataSchema (a JSON
// schema object; nil means any object). MCP tools declare it as their
// outputSchema.
func OperationSchema(op Operation, dataSchema json.RawMessage) ([]byte, error) {
	return OperationsSchema([]Operation{op}, dataSchema)
}

// OperationsSchema is [OperationSchema] for a tool whose operation depends
// on its arguments (for example `update` → update.plan, update.apply or
// update.check). All operations share one data schema.
func OperationsSchema(ops []Operation, dataSchema json.RawMessage) ([]byte, error) {
	if len(ops) == 0 {
		return nil, errors.New("at least one operation is required")
	}
	root := baseSchema(true)
	props := root["properties"].(map[string]any)
	var allOf, projectOps []any
	allGlobal := true
	for _, op := range ops {
		spec, ok := operationRegistry[op]
		if !ok {
			return nil, fmt.Errorf("unsupported result operation %q", op)
		}
		if spec.scope != ScopeGlobal {
			allGlobal = false
		}
		if spec.scope == ScopeProject {
			projectOps = append(projectOps, string(op))
		}
	}
	if len(ops) == 1 {
		op := ops[0]
		props["operation"] = map[string]any{"const": string(op)}
		props["kind"] = map[string]any{"const": operationRegistry[op].kind}
	} else {
		var names, kinds []any
		for _, op := range ops {
			spec := operationRegistry[op]
			names = append(names, string(op))
			kinds = append(kinds, spec.kind)
			allOf = append(allOf, map[string]any{
				"if":   map[string]any{"properties": map[string]any{"operation": map[string]any{"const": string(op)}}, "required": []any{"operation"}},
				"then": map[string]any{"properties": map[string]any{"kind": map[string]any{"const": spec.kind}}},
			})
		}
		props["operation"] = map[string]any{"enum": names}
		props["kind"] = map[string]any{"enum": sortedUnique(kinds)}
	}
	if allGlobal {
		props["project"] = map[string]any{"type": "null"}
	}
	if len(projectOps) > 0 {
		allOf = append(allOf, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"operation": map[string]any{"enum": projectOps},
					"status":    map[string]any{"enum": []any{string(StatusOK), string(StatusChanges), string(StatusConflicted)}},
				},
				"required": []any{"operation", "status"},
			},
			"then": map[string]any{"properties": map[string]any{"project": map[string]any{"$ref": "#/$defs/project"}}},
		})
	}
	if len(allOf) > 0 {
		root["allOf"] = allOf
	}
	if len(dataSchema) > 0 {
		var data map[string]any
		if err := json.Unmarshal(dataSchema, &data); err != nil || data == nil {
			return nil, fmt.Errorf("data schema for %v must be a JSON object", ops)
		}
		// Nested $defs are hoisted so that the tool schema stays a single
		// self-contained document.
		if defs, ok := data["$defs"].(map[string]any); ok {
			rootDefs := root["$defs"].(map[string]any)
			for name, def := range defs {
				if _, clash := rootDefs[name]; clash {
					return nil, fmt.Errorf("data schema for %v redefines $defs/%s", ops, name)
				}
				rootDefs[name] = def
			}
			delete(data, "$defs")
		}
		delete(data, "$schema")
		delete(data, "$id")
		props["data"] = data
	}
	return encodeSchema(root)
}

// baseSchema returns the envelope schema. The compact form, used for MCP
// tool outputSchemas that agents read on every tools/list, keeps the
// structure (required keys, types, enums, the project rule) and drops the
// string-format rules; [Result.Validate] enforces those on both sides of the
// transport, and the published schema file carries them in full.
func baseSchema(compact bool) map[string]any {
	if compact {
		return compactBaseSchema()
	}
	relativePath := map[string]any{
		"type": "string", "minLength": 1,
		"pattern": `^[^/\\]+(/[^/\\]+)*$`,
		"not":     map[string]any{"pattern": `(^|/)\.{1,2}(/|$)`},
	}
	absolutePath := map[string]any{
		"type": "string", "minLength": 1,
		"anyOf": []any{
			map[string]any{"pattern": "^/"},
			map[string]any{"pattern": `^[A-Za-z]:[/\\]`},
			map[string]any{"pattern": `^\\\\`},
		},
	}
	blockID := map[string]any{"type": "string", "pattern": `^[A-Za-z][A-Za-z0-9._-]{0,127}$`}
	digest := map[string]any{"type": "string", "pattern": `^sha256:[a-f0-9]{64}$`}
	project := map[string]any{
		"type":     "object",
		"required": []any{"id", "root"},
		"properties": map[string]any{
			"id":   map[string]any{"type": "string", "minLength": 1},
			"root": map[string]any{"$ref": "#/$defs/absolutePath"},
		},
		"additionalProperties": true,
	}
	nonNegative := map[string]any{"type": "integer", "minimum": 0}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   "tplaiter result/v1 envelope",
		"type":    "object",
		"$defs": map[string]any{
			"relativePath": relativePath,
			"absolutePath": absolutePath,
			"project":      project,
		},
		"required": []any{"apiVersion", "kind", "operation", "status", "project", "transactionId", "summary", "changes", "diagnostics", "artifacts", "meta"},
		"properties": map[string]any{
			"apiVersion":    map[string]any{"const": APIVersion},
			"status":        map[string]any{"enum": []any{"ok", "changes", "conflicted", "blocked", "failed", "not-applicable"}},
			"transactionId": map[string]any{"type": []any{"string", "null"}, "minLength": 1},
			"project":       map[string]any{"anyOf": []any{map[string]any{"type": "null"}, map[string]any{"$ref": "#/$defs/project"}}},
			"summary": map[string]any{
				"type": "object", "required": []any{"filesChanged", "blocksChanged", "conflicts"},
				"properties":           map[string]any{"filesChanged": nonNegative, "blocksChanged": nonNegative, "conflicts": nonNegative},
				"additionalProperties": true,
			},
			"changes": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "required": []any{"path", "action"},
				"properties": map[string]any{
					"path": map[string]any{"$ref": "#/$defs/relativePath"}, "blockId": blockID,
					"provider": map[string]any{"type": "string", "minLength": 1}, "action": map[string]any{"type": "string", "minLength": 1},
				},
				"additionalProperties": true,
			}},
			"diagnostics": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "required": []any{"code", "severity", "message", "details"},
				"properties": map[string]any{
					"code": map[string]any{"type": "string", "minLength": 1}, "severity": map[string]any{"enum": []any{"error", "warning", "info"}},
					"message": map[string]any{"type": "string", "minLength": 1}, "path": map[string]any{"$ref": "#/$defs/relativePath"},
					"blockId": blockID, "hint": map[string]any{"type": "string"}, "details": map[string]any{"type": "object"},
				},
				"additionalProperties": true,
			}},
			"artifacts": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "required": []any{"name", "path", "sha256"},
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "minLength": 1}, "path": map[string]any{"$ref": "#/$defs/relativePath"}, "sha256": digest,
				},
				"additionalProperties": true,
			}},
			"meta": map[string]any{
				"type": "object", "required": []any{"tplaiterVersion", "schemaVersion"},
				"properties": map[string]any{
					"tplaiterVersion": map[string]any{"type": "string", "minLength": 1},
					"schemaVersion":   map[string]any{"const": SchemaVersion},
				},
				"additionalProperties": true,
			},
			"planSha256": digest,
			"currentRef": map[string]any{"type": "string"},
			"targetRef":  map[string]any{"type": "string"},
			"data":       map[string]any{"type": "object"},
		},
		"additionalProperties": true,
	}
}

func sortedUnique(values []any) []any {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		s := v.(string)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// Operations are sorted; kinds follow a different order, so sort them.
	sort.Strings(out)
	res := make([]any, len(out))
	for i, s := range out {
		res[i] = s
	}
	return res
}

func encodeSchema(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compactBaseSchema() map[string]any {
	str := map[string]any{"type": "string"}
	count := map[string]any{"type": "integer", "minimum": 0}
	object := func(required []any, props map[string]any) map[string]any {
		return map[string]any{"type": "object", "required": required, "properties": props}
	}
	return map[string]any{
		"type": "object",
		"$defs": map[string]any{
			"project": object([]any{"id", "root"}, map[string]any{"id": str, "root": str}),
		},
		"required": []any{"apiVersion", "kind", "operation", "status", "project", "transactionId", "summary", "changes", "diagnostics", "artifacts", "meta"},
		"properties": map[string]any{
			"apiVersion":    map[string]any{"const": APIVersion},
			"status":        map[string]any{"enum": []any{"ok", "changes", "conflicted", "blocked", "failed", "not-applicable"}},
			"transactionId": map[string]any{"type": []any{"string", "null"}},
			"project":       map[string]any{"anyOf": []any{map[string]any{"type": "null"}, map[string]any{"$ref": "#/$defs/project"}}},
			"summary":       object([]any{"filesChanged", "blocksChanged", "conflicts"}, map[string]any{"filesChanged": count, "blocksChanged": count, "conflicts": count}),
			"changes": map[string]any{"type": "array", "items": object([]any{"path", "action"}, map[string]any{
				"path": str, "blockId": str, "provider": str, "action": str,
			})},
			"diagnostics": map[string]any{"type": "array", "items": object([]any{"code", "severity", "message", "details"}, map[string]any{
				"code": str, "severity": map[string]any{"enum": []any{"error", "warning", "info"}}, "message": str,
				"path": str, "blockId": str, "hint": str, "details": map[string]any{"type": "object"},
			})},
			"artifacts": map[string]any{"type": "array", "items": object([]any{"name", "path", "sha256"}, map[string]any{"name": str, "path": str, "sha256": str})},
			"meta":      object([]any{"tplaiterVersion", "schemaVersion"}, map[string]any{"tplaiterVersion": str, "schemaVersion": map[string]any{"const": SchemaVersion}}),
			"data":      map[string]any{"type": "object"},
		},
	}
}
