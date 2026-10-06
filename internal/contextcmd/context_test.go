package contextcmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
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

func TestLocalProviderUnavailableProjection(t *testing.T) {
	unavailable := &trustload.LocalProviderUnavailableError{}
	if !errors.Is(unavailable, trustload.ErrLocalProvider) {
		t.Fatal("legacy refusal compatibility lost")
	}
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"typed", unavailable, "LOCAL_PROVIDER_UNAVAILABLE"},
		{"wrapped-typed", fmt.Errorf("neutral wrapper: %w", unavailable), "LOCAL_PROVIDER_UNAVAILABLE"},
		{"raw-refusal", trustload.ErrLocalProvider, "CONTEXT_AUTHENTICATION_FAILED"},
		{"wrapped-refusal", fmt.Errorf("neutral wrapper: %w", trustload.ErrLocalProvider), "CONTEXT_AUTHENTICATION_FAILED"},
		{"text-lookalike", errors.New("LOCAL_PROVIDER_UNAVAILABLE"), "CONTEXT_AUTHENTICATION_FAILED"},
		{"platform", trustload.ErrLocalUnsupported, "CONTEXT_AUTHENTICATION_FAILED"},
		{"pin", trustload.ErrPinMismatch, "CONTEXT_AUTHENTICATION_FAILED"},
		{"config", trustload.ErrConfigInvalid, "CONTEXT_AUTHENTICATION_FAILED"},
		{"canceled", context.Canceled, "CONTEXT_CANCELLED"},
		{"deadline", context.DeadlineExceeded, "CONTEXT_CANCELLED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Code(tc.err); got != tc.code {
				t.Fatalf("code = %s, want %s", got, tc.code)
			}
			// The installed local-preview route chooses ExitUnavailable (8).
			// Ordinary context.go chooses ExitTrust (5); neither route changes.
			projected := resultdto.NewError(Code(tc.err), resultdto.ExitUnavailable, tc.err)
			if resultdto.Classify(projected) != resultdto.ExitUnavailable || int(resultdto.Classify(projected)) != 8 {
				t.Fatal("existing CLI preview exit changed")
			}
			trustFailure := resultdto.NewError(Code(tc.err), resultdto.ExitTrust, tc.err)
			if resultdto.Classify(trustFailure) != resultdto.ExitTrust {
				t.Fatal("ordinary context trust exit changed")
			}
			diagnostics := resultdto.ProjectDiagnostics(projected)
			if len(diagnostics) != 1 || diagnostics[0].Code != tc.code || diagnostics[0].Severity != "error" || diagnostics[0].Message != "lifecycle operation failed" || diagnostics[0].Details == nil || len(diagnostics[0].Details) != 0 {
				t.Fatal("safe diagnostic projection changed")
			}
			if diagnostics[0].Path != "" || diagnostics[0].BlockID != "" {
				t.Fatal("diagnostic acquired private context")
			}
			if tc.code == "LOCAL_PROVIDER_UNAVAILABLE" {
				envelope := resultdto.New(resultdto.OperationContextQuery, "dev")
				envelope.Status = resultdto.StatusForExit(projected.ExitCode())
				envelope.Diagnostics = diagnostics
				b, err := resultdto.MarshalCanonical(envelope)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := resultdto.Decode(b)
				if err != nil || decoded.Status != resultdto.StatusBlocked || len(decoded.Data) != 0 || decoded.Project != nil || decoded.TransactionID != nil || decoded.Summary != (resultdto.Summary{}) || len(decoded.Changes) != 0 || len(decoded.Artifacts) != 0 {
					t.Fatal("blocked envelope acquired effect or preview data")
				}
				t.Logf("actual safe result/v1 projection: %s; exit=%d", b, projected.ExitCode())
			}
		})
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
