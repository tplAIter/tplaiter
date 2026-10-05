package contextcmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestLocalPreviewClosedRequestAndURI(t *testing.T) {
	for _, raw := range []string{`{"registrationID":"local","socketPath":"/caller"}`, `{"registrationID":"local","trusted":true}`, `{"registrationID":"local","command":"launch"}`} {
		var r LocalPreviewRequest
		if canonicaljson.DecodeStrict([]byte(raw), &r) == nil {
			t.Fatal("caller connection authority")
		}
	}
	pin := "sha256:"
	for range 64 {
		pin += "a"
	}
	uri := PreviewResourceURI("project", "local", pin, "example:source:a", "example:asset:readme")
	project, r, err := ParsePreviewResourceURI(uri)
	if err != nil || project != "project" || r.SourceID != "example:source:a" {
		t.Fatal(uri, err)
	}
	if _, _, err = ParsePreviewResourceURI(uri + "?socket=/caller"); err == nil {
		t.Fatal("URI caller endpoint")
	}
	if _, err = RunLocalPreview(context.Background(), nil, "preview-catalog", LocalPreviewRequest{RegistrationID: "local"}); err == nil {
		t.Fatal("nil runtime")
	}
	if err = NormalizeLocalPreview("continue", &r); err == nil {
		t.Fatal("cross-session producer cursor")
	}
	legacy := resultdto.ContextData{Action: "discover", Entries: []resultdto.ContextEntry{}, WindowState: "unknown"}
	raw, _ := json.Marshal(legacy)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if fields["localPreview"] != nil {
		t.Fatal("native output changed")
	}
}

func TestLocalPreviewRegistrationLexicalParity(t *testing.T) {
	for _, tc := range []struct {
		value   string
		allowed bool
	}{
		{"host\x00preview", false},
		{"host\tpreview", false},
		{"host\rpreview", false},
		{"host\npreview", false},
		{"host preview", false},
		{"host/preview", false},
		{"host\\preview", false},
		{"host\fpreview", true},
		{"host\vpreview", true},
		{"host\u00a0preview", true},
		{"host\u2003preview", true},
		{"hôte-文", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("é", 32), true},
		{strings.Repeat("é", 33), false},
		{string([]byte{'h', 0xff}), false},
	} {
		req := LocalPreviewRequest{RegistrationID: tc.value}
		if got := NormalizeLocalPreview("preview-catalog", &req) == nil; got != tc.allowed {
			t.Fatalf("registration %q admitted=%v want %v", tc.value, got, tc.allowed)
		}
	}
}
