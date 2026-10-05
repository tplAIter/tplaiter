package providerclient

import "encoding/json"

type catalogParts struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	ID         string            `json:"id"`
	Version    string            `json:"version"`
	Sources    []json.RawMessage `json:"sources"`
	Items      []json.RawMessage `json:"items"`
	Edges      []json.RawMessage `json:"edges"`
}

func parts(raw []byte) (catalogParts, error) {
	var p catalogParts
	// C01 nullable defaults are intentionally opaque here. Each entire object is
	// compared to a validated frozen object, then the merged bytes use C01 Decode.
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || len(envelope) != 7 || !jsonEqual(raw, raw) || !required(raw, "apiVersion", "kind", "id", "version", "sources", "items", "edges") || json.Unmarshal(raw, &p) != nil || p.Sources == nil || p.Items == nil || p.Edges == nil {
		return p, failure("SESSION_WIRE", nil)
	}
	return p, nil
}

func objectString(raw []byte, key string) string {
	var m map[string]json.RawMessage
	var s string
	if json.Unmarshal(raw, &m) == nil {
		_ = json.Unmarshal(m[key], &s)
	}
	return s
}

func containsObject(objects []json.RawMessage, id string, raw []byte) bool {
	if id == "" {
		return false
	}
	for _, obj := range objects {
		if objectString(obj, "id") == id {
			return jsonEqual(obj, raw)
		}
	}
	return false
}

func edgeKey(raw []byte) string {
	return objectString(raw, "from") + "\x00" + objectString(raw, "to") + "\x00" + objectString(raw, "layer") + "\x00" + objectString(raw, "relation")
}

func containsEdge(edges []json.RawMessage, key string, raw []byte) bool {
	for _, obj := range edges {
		if edgeKey(obj) == key {
			return jsonEqual(obj, raw)
		}
	}
	return false
}

func containsID(p catalogParts, id string) bool {
	for _, xs := range [][]json.RawMessage{p.Sources, p.Items} {
		for _, obj := range xs {
			if objectString(obj, "id") == id {
				return true
			}
		}
	}
	return false
}
