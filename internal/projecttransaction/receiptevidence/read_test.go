package receiptevidence

import (
	"context"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"testing"
)

func TestReadRejectsUnboundAndMalformedReceiptInputs(t *testing.T) {
	for _, tc := range []struct{ home, id string }{{"relative", "00000000000000000000000000000000"}, {"/tmp", "bad"}} {
		if _, err := Read(context.Background(), nil, tc.home, tc.id); err == nil {
			t.Fatalf("accepted invalid input: %#v", tc)
		}
	}
	var j *Journal
	if err := j.RecheckFor(context.Background(), nil); err == nil {
		t.Fatal("nil journal recheck succeeded")
	}
}

func TestReceiptClosedWireCounters(t *testing.T) {
	for _, raw := range []string{`null`, `[256]`, `[-1]`, `"AQ=="`} {
		var b wireBytes
		if json.Unmarshal([]byte(raw), &b) == nil {
			t.Fatal("invalid integer byte wire", raw)
		}
	}
	for _, raw := range []string{
		`{"apiVersion":"tplaiter.dev/project-transaction/v1","kind":"NativeUpdateTransaction","id":"a","unknown":1}`,
		`{"apiVersion":"tplaiter.dev/project-transaction/v1","kind":"NativeUpdateTransaction","id":"a","id":"a"}`,
		`{"apiVersion":"tplaiter.dev/project-transaction/v1","kind":"NativeUpdateTransaction","id":"a","steps":null}`,
	} {
		var state wireState
		if canonicaljson.DecodeStrict([]byte(raw), &state) == nil {
			t.Fatal("non-closed state accepted", raw)
		}
	}
	var zero Journal
	if _, err := zero.Record(context.Background(), nil, "state.json"); err == nil {
		t.Fatal("unowned journal accepted")
	}
	if zero.Close() == nil {
		t.Fatal("unowned close accepted")
	}
}
