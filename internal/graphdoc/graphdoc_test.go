package graphdoc

import (
	"strings"
	"testing"
)

func TestJSONRoundTripAndStrictTopology(t *testing.T) {
	d := New()
	d.Nodes = []Node{{ID: "a", Kind: "file"}, {ID: "b", Kind: "declaration"}}
	d.Edges = []Edge{{From: "a", To: "b", Kind: "declares"}}
	raw, err := JSON(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest == "" {
		t.Fatal("missing digest")
	}
	got.Edges = append(got.Edges, got.Edges[0])
	if err := Validate(got); err == nil {
		t.Fatal("duplicate edge accepted")
	}
}

func TestDecodeRejectsDuplicateKeysAndUnboundedFields(t *testing.T) {
	d := New()
	d.Nodes = []Node{{ID: "a", Kind: "file"}}
	raw, err := JSON(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), `"kind": "Graph"`, `"kind":"Graph","kind":"Graph"`, 1)),
		[]byte(strings.Replace(string(raw), `"id": "a"`, `"id":"a","id":"a"`, 1)),
		[]byte(strings.Replace(string(raw), `"nodes": [`, `"nodes":[],"nodes":[`, 1)),
	} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted duplicate JSON key: %s", bad)
		}
	}
	d.Nodes[0].Attributes = map[string]string{strings.Repeat("k", MaxString+1): "value"}
	if err := Validate(d); err == nil {
		t.Fatal("accepted oversized attribute key")
	}
	d = New()
	d.Nodes = []Node{{ID: "a", Kind: "file"}}
	d.Diagnostics = []Diagnostic{{Code: "c", Severity: "bogus", Message: "m"}}
	if err := Validate(d); err == nil {
		t.Fatal("accepted unknown diagnostic severity")
	}
}
