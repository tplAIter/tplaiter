package resultdto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Canonical returns a normalized copy with deterministically ordered
// collections. It does not mutate caller-owned slices or maps and is
// therefore safe at API boundaries. Invalid data bytes are left unchanged;
// [MarshalCanonical] reports them.
func (r Result) Canonical() Result {
	out, err := r.canonical()
	if err != nil {
		return r.canonicalCollections()
	}
	return out
}

func (r Result) canonical() (Result, error) {
	r = r.canonicalCollections()
	if len(r.Data) == 0 {
		r.Data = nil
		return r, nil
	}
	data, err := canonicalJSON(r.Data)
	if err != nil {
		return r, fmt.Errorf("result data: %w", err)
	}
	r.Data = data
	return r, nil
}

func (r Result) canonicalCollections() Result {
	r.Changes = append([]Change{}, r.Changes...)
	r.Diagnostics = append([]Diagnostic{}, r.Diagnostics...)
	r.Artifacts = append([]Artifact{}, r.Artifacts...)
	if r.Project != nil {
		p := *r.Project
		r.Project = &p
	}
	if r.TransactionID != nil {
		tx := *r.TransactionID
		r.TransactionID = &tx
	}
	for i := range r.Diagnostics {
		r.Diagnostics[i].Details = cloneDetails(r.Diagnostics[i].Details)
	}
	sort.SliceStable(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.BlockID != b.BlockID {
			return a.BlockID < b.BlockID
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.Action < b.Action
	})
	sort.SliceStable(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.BlockID != b.BlockID {
			return a.BlockID < b.BlockID
		}
		if a.Message != b.Message {
			return a.Message < b.Message
		}
		if a.Hint != b.Hint {
			return a.Hint < b.Hint
		}
		// Two diagnostics that differ only in Details still need a stable
		// order. encoding/json sorts object keys, so this is also stable for
		// nested decoded JSON objects.
		return canonicalDetails(a.Details) < canonicalDetails(b.Details)
	})
	sort.SliceStable(r.Artifacts, func(i, j int) bool {
		a, b := r.Artifacts[i], r.Artifacts[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.SHA256 < b.SHA256
	})
	return r
}

// canonicalJSON re-encodes raw with sorted object keys and no insignificant
// whitespace. Numbers keep their literal spelling.
func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("data must be a JSON object")
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

func cloneDetails(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneJSONValue(v)
	}
	return out
}

func cloneJSONValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		return cloneDetails(v)
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = cloneJSONValue(v[i])
		}
		return out
	default:
		return v
	}
}

func canonicalDetails(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Validate reports an unsupported JSON value before a result can be
		// emitted. Keeping invalid values equal here avoids panicking while
		// sorting an invalid caller-owned DTO.
		return ""
	}
	return string(b)
}
