package resultdto

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

// VolatileProjectRoot replaces a temporary project root during parity
// comparison.
const VolatileProjectRoot = "/volatile/project-root"

// volatileKeys are the only data/details keys whose values differ between
// two independent but equivalent runs: timestamps and wall-clock durations.
var volatileKeys = map[string]bool{
	"createdAt":  true,
	"updatedAt":  true,
	"lastSeenAt": true,
	"durationMs": true,
}

// NormalizeVolatile prepares a result for CLI↔MCP parity comparison of two
// independent runs. It replaces ONLY the allowlisted volatile fields:
//
//   - transactionId (set to null);
//   - project.root when it lies under one of tempRoots (a temporary test
//     root), replaced by [VolatileProjectRoot];
//   - timestamp and duration keys (createdAt, updatedAt, lastSeenAt,
//     durationMs) inside data and diagnostic details, replaced by "volatile".
//
// kind, operation, status, summary, changes, diagnostic codes and messages,
// artifacts and every other data field are never normalized.
func NormalizeVolatile(r Result, tempRoots ...string) Result {
	r = r.canonicalCollections()
	r.TransactionID = nil
	if r.Project != nil && underAny(r.Project.Root, tempRoots) {
		r.Project.Root = VolatileProjectRoot
	}
	for i := range r.Diagnostics {
		r.Diagnostics[i].Details, _ = normalizeVolatileValue(r.Diagnostics[i].Details).(map[string]any)
	}
	if len(r.Data) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(r.Data))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) == nil {
			if raw, err := json.Marshal(normalizeVolatileValue(value)); err == nil {
				r.Data = raw
			}
		}
	}
	return r
}

func normalizeVolatileValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			if volatileKeys[k] {
				out[k] = "volatile"
				continue
			}
			out[k] = normalizeVolatileValue(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = normalizeVolatileValue(v[i])
		}
		return out
	default:
		return v
	}
}

func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}
