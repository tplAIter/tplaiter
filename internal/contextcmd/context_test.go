package contextcmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/knowledge"
)

func TestContextAdapterMatchesC03Identifiers(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/knowledge/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := knowledge.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := contextindex.New(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	all, err := idx.Retrieve(context.Background(), contextindex.Request{Limit: 64, MaxBytes: 32768}, nil)
	if err != nil {
		t.Fatal(err)
	}
	listed := entries(d)
	if len(listed) != len(all.Records) {
		t.Fatal("identifier projection length")
	}
	for n, e := range listed {
		if e.ID != all.Records[n].ID || e.Path != all.Records[n].Path || e.Kind != all.Records[n].Kind {
			t.Fatalf("adapter/core mismatch: %+v %+v", e, all.Records[n])
		}
	}
	d.Items[0], d.Items[2] = d.Items[2], d.Items[0]
	if !reflect.DeepEqual(listed, entries(d)) {
		t.Fatal("input permutation changes IDs")
	}
}

func TestContextCursorQueryScopeBoundsAndURIs(t *testing.T) {
	req := Request{Action: "search", Kind: "resource", Required: []string{"installed:resource:floor"}, Limit: 1, MaxBytes: 8192}
	if err := normalize(&req); err != nil {
		t.Fatal(err)
	}
	snapshot := "sha256:" + string(make([]byte, 64))
	bound := requestBinding(req, snapshot)
	c := cursor{Version: "tplaiter.dev/context-cursor/v1", Binding: bound, Offset: 1, Request: req}
	raw, _ := json.Marshal(c)
	decoded, err := decodeCursor(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil || decoded.Binding != bound {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Text = "other" }, func(r *Request) { r.MaxBytes-- }, func(r *Request) { r.Required = nil }} {
		changed := req
		mutate(&changed)
		if requestBinding(changed, snapshot) == bound {
			t.Fatal("query/bounds/floor cursor binding unchanged")
		}
	}
	if requestBinding(req, "other-scope-snapshot") == bound {
		t.Fatal("scope binding unchanged")
	}
	uri := ResourceURI("project", "sha256:abc", "installed:resource:r-abc")
	key, pin, id, err := ParseResourceURI(uri)
	if err != nil || key != "project" || pin != "sha256:abc" || id != "installed:resource:r-abc" {
		t.Fatal(uri, err)
	}
	for _, bad := range []string{uri + "?maxBytes=1", uri + "#x", "tplaiter://context/key/pin/%2e%2e%2fsecret"} {
		if _, _, _, err = ParseResourceURI(bad); err == nil {
			t.Fatal("unsafe resource", bad)
		}
	}
	if Code(context.Canceled) != "CONTEXT_CANCELLED" || !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("cancellation code")
	}
}
