package canonicaljson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRFC8785CanonicalVectors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"object-order", `{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{"utf16-order", `{"\uE000":1,"\uD834\uDD1E":2}`, `{"𝄞":2,"":1}`},
		{"numbers", `[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]`, `[333333333.3333333,1e+30,4.5,0.002,1e-27]`},
		{"controls", `{"x":"\u000f\n\\\""}`, `{"x":"\u000f\n\\\""}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestDecodeStrictAcceptsOpaqueRawMessageObject(t *testing.T) {
	t.Parallel()
	type wire struct {
		Payload json.RawMessage `json:"payload"`
	}
	var got wire
	if err := DecodeStrict([]byte(`{"payload":{"b":2,"a":1}}`), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != `{"b":2,"a":1}` {
		t.Fatalf("payload=%s", got.Payload)
	}
	for _, input := range []string{`{"payload":null}`, `{"payload":{"a":1,"a":2}}`, `{"payload":{}} {}`} {
		if err := DecodeStrict([]byte(input), &got); err == nil {
			t.Fatalf("accepted malformed raw payload %s", input)
		}
	}
}

func TestCanonicalRejectsDuplicateAndTrailingValues(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"a":1,"a":2}`, `{} {}`, `{"x":"\uD800"}`, `{"x":"\uDC00"}`} {
		if _, err := Canonicalize([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestDecodeStrictRejectsNullUnknownAndFoldedFields(t *testing.T) {
	t.Parallel()
	type wire struct {
		Name string `json:"name"`
	}
	for _, input := range []string{`{"name":null}`, `{"name":"ok","extra":1}`, `{"Name":"ok"}`, `{"name":"a","name":"b"}`} {
		var got wire
		if err := DecodeStrict([]byte(input), &got); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	var got wire
	if err := DecodeStrict([]byte(`{"name":"ok"}`), &got); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got.Name) != "ok" {
		t.Fatalf("decoded %#v", got)
	}
}

func TestCanonicalRejectsInvalidGoUTF8(t *testing.T) {
	t.Parallel()
	bad := string([]byte{0xff})
	for name, value := range map[string]any{
		"string": bad,
		"value":  map[string]string{"value": bad},
		"key":    map[string]string{bad: "value"},
		"nested": struct {
			Values []string `json:"values"`
		}{Values: []string{bad}},
	} {
		if _, err := Canonical(value); err == nil {
			t.Errorf("%s: accepted invalid UTF-8", name)
		}
	}
	if got, err := Canonical("\uFFFD"); err != nil || string(got) != `"�"` {
		t.Fatalf("valid replacement character: got %s, err %v", got, err)
	}
}

func TestCanonicalRejectsCyclicMapsAndSlices(t *testing.T) {
	t.Parallel()
	m := map[string]any{}
	m["self"] = m
	if _, err := Canonical(m); err == nil {
		t.Fatal("accepted cyclic map")
	}
	s := []any{nil}
	s[0] = s
	if _, err := Canonical(s); err == nil {
		t.Fatal("accepted cyclic slice")
	}
	shared := map[string]any{"value": "ok"}
	if _, err := Canonical([]any{shared, shared}); err != nil {
		t.Fatalf("rejected acyclic alias: %v", err)
	}
}
