package actioncmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestRunBatchMissingCarrierRefuses(t *testing.T) {
	if s, e := PrepareRunBatch(context.Background(), nil, nil, operationtrust.RunBatchInput{}); s != nil || e == nil {
		t.Fatal("no live carrier admitted")
	}
	for _, s := range []*BatchSession{nil, {}} {
		if _, e := s.Requests(); e == nil {
			t.Fatal("nil requests")
		}
		if e := s.Recheck(context.Background()); e == nil {
			t.Fatal("nil recheck")
		}
		if _, e := s.Execute(context.Background(), []trustverify.ApprovalRefs{}); e == nil {
			t.Fatal("nil execution")
		}
		if e := s.EnterBootstrap(context.Background(), execx.ActionBootstrapControl{}); e == nil {
			t.Fatal("nil bootstrap")
		}
		s.Close()
		s.Close()
	}
}

func TestRunBatchFactualPartialHandoffDoesNotAliasOrGrant(t *testing.T) {
	code := 7
	zero := 0
	original := &BatchResult{APIVersion: "tplaiter.dev/action-batch-receipt/v1", Disposition: "recovery-required", Steps: []BatchStepResult{{Ordinal: 0, State: "observed", Receipt: &execx.ActionProcessResult{ChildExitCode: &code, PersistentWrites: &zero, Stdout: []byte("actual returned facts"), Cleanup: "reaped"}}, {Ordinal: 1, State: "attempted-unknown"}, {Ordinal: 2, State: "unstarted"}}}
	s := &BatchSession{outcome: original}
	out := s.Outcome()
	if out.Steps[0].Receipt == nil || *out.Steps[0].Receipt.ChildExitCode != 7 || out.Steps[1].Receipt != nil || out.Steps[1].State != "attempted-unknown" || out.Steps[2].State != "unstarted" {
		t.Fatal("known/unknown facts lost")
	}
	out.Steps[0].Receipt.Stdout[0] = 'X'
	*out.Steps[0].Receipt.ChildExitCode = 0
	if string(s.Outcome().Steps[0].Receipt.Stdout) != "actual returned facts" || *s.Outcome().Steps[0].Receipt.ChildExitCode != 7 {
		t.Fatal("handoff aliases")
	}
	if _, e := s.Execute(context.Background(), nil); e == nil {
		t.Fatal("factual body recreated session authority")
	}
	s.Close()
	if s.Outcome().Steps[0].Receipt == nil {
		t.Fatal("close discarded observed facts")
	}
}

func TestRunBatchBootstrapActualCanonicalCeiling(t *testing.T) {
	d := evidencecas.Digest([]byte("finite control test transport, not a signed grant"))
	in := operationtrust.RunBatchInput{APIVersion: "tplaiter.dev/run-batch-input/v1", Steps: []operationtrust.BatchStep{{Name: "first", Parameters: json.RawMessage(`{}`)}, {Name: "second", Parameters: json.RawMessage(`{}`)}}}
	requests := []trustverify.ExecutionRequest{{RequestSHA256: d}, {RequestSHA256: d}}
	refs := []trustverify.ApprovalRefs{{Kind: "persistent-signed", ApprovalCAS: d}, {Kind: "persistent-signed", ApprovalCAS: d}}
	if e := execx.PreflightActionBatchControls("neutral-project", in, requests, refs); e != nil {
		t.Fatal(e)
	}
	if e := execx.PreflightActionBatchControls(strings.Repeat("a", 64<<10), in, requests, refs); e == nil {
		t.Fatal("oversized complete control admitted")
	}
	if e := execx.PreflightActionBatchControls("neutral-project", in, requests, refs[:1]); e == nil {
		t.Fatal("dropped approval admitted")
	}
	bad := append([]trustverify.ApprovalRefs(nil), refs...)
	bad[1].Kind = "caller-bool"
	if e := execx.PreflightActionBatchControls("neutral-project", in, requests, bad); e == nil {
		t.Fatal("unapproved reference kind admitted")
	}
	// Added fields must remain absent in exact single-action canonical v1 wire.
	control := execx.ActionBootstrapControl{APIVersion: "tplaiter.dev/action-bootstrap/v1", ProjectContext: "neutral", ActionID: "first", Parameters: json.RawMessage(`{}`), ApprovalCAS: d, RequestSHA256: d, SessionSHA256: d}
	raw, e := canonicaljson.Canonical(control)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 7 || fields["batch"] != nil || fields["ordinal"] != nil || fields["approvals"] != nil {
		t.Fatal("v1 bytes widened")
	}
}
