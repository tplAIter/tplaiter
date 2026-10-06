package operationtrust

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestRunBatchClosedInput(t *testing.T) {
	good := []byte(`{"apiVersion":"tplaiter.dev/run-batch-input/v1","steps":[{"name":"check","parameters":{}}]}`)
	if _, e := DecodeRunBatchInput(good); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{
		bytes.Replace(good, []byte(`"name":"check"`), []byte(`"name":"check","name":"other"`), 1),
		bytes.Replace(good, []byte(`"parameters":{}`), []byte(`"parameters":{"x":1,"x":2}`), 1),
		bytes.Replace(good, []byte(`"parameters":{}`), []byte(`"parameters":null`), 1),
		bytes.Replace(good, []byte(`"parameters":{}`), []byte(`"parameters":{},"permit":true`), 1),
		[]byte(`{"apiVersion":"tplaiter.dev/run-batch-input/v1","steps":[]}`),
		append(good, good...), []byte(strings.Repeat(" ", MaxRunBatchInput+1)),
	} {
		if _, e := DecodeRunBatchInput(raw); e == nil {
			t.Fatal("malformed batch admitted")
		}
	}
	in := RunBatchInput{APIVersion: "tplaiter.dev/run-batch-input/v1", Steps: make([]BatchStep, MaxRunBatchSteps+1)}
	for i := range in.Steps {
		in.Steps[i] = BatchStep{Name: "check", Parameters: json.RawMessage(`{}`)}
	}
	raw, _ := canonicaljson.Canonical(in)
	if _, e := DecodeRunBatchInput(raw); e == nil {
		t.Fatal("17 steps admitted")
	}
	if _, e := PrepareRunBatch(context.Background(), nil, nil, in); e == nil {
		t.Fatal("no live runtime admitted")
	}
}

// This pure hashing fixture is NOT a prepared source, permit or native grant.
func batchHashOriginal(t *testing.T, name string) *ActionSelection {
	t.Helper()
	d := evidencecas.Digest([]byte("neutral closed hash fixture"))
	p := actionTestDocument().Actions[0].Tool.Provider
	cap := []byte(`{"apiVersion":"neutral-hash-test"}`)
	content := []trustverify.ContentEntry{{Root: "provider", Path: actionCapsulePath, Mode: "100644", ContentSHA256: evidencecas.Digest(cap)}}
	closure, e := trustverify.ComputeContentClosureSHA256(content)
	if e != nil {
		t.Fatal(e)
	}
	options, e := trustverify.ComputeToolOptionsSHA256([]string{})
	if e != nil {
		t.Fatal(e)
	}
	material := trustverify.ActionMaterial{Provider: p, Action: trustverify.Action{ID: name, Kind: "command", Phase: "standalone", Argv: []string{"checker"}, ContentClosureSHA256: closure}, Tool: trustverify.Tool{ID: "checker", Version: "1.0", BinarySHA256: d, OptionsSHA256: options}, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "provider", Path: ".tplaiter-execution"}, EnvironmentPolicySHA256: d, TimeoutMillis: 1000, Migration: trustverify.Migration{Kind: "none"}}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: d, ProjectID: "neutral", Scope: "run", PreimageSHA256: d, AnswersSHA256: d, Subjects: []trustverify.Provider{p}, Actions: []trustverify.ActionMaterial{material}}
	digest, e := trustverify.ComputeOperationInputsSHA256(op)
	if e != nil {
		t.Fatal(e)
	}
	req := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: d, OperationInputsSHA256: digest, ProjectID: op.ProjectID, Scope: "run", Provider: p, Action: material.Action, Tool: material.Tool, WorkingDirectoryScope: material.WorkingDirectoryScope, EnvironmentPolicySHA256: d, TimeoutMillis: 1000, Migration: material.Migration}
	req.RequestSHA256, e = req.ComputeRequestSHA256()
	if e != nil {
		t.Fatal(e)
	}
	return &ActionSelection{operation: op, request: req, capsule: cap, content: content, contentBytes: [][]byte{append([]byte(nil), cap...)}}
}

func TestRunBatchOrdinalFinalizationPreservesSingleAction(t *testing.T) {
	build := func(names []string) *RunBatchSelection {
		b := &RunBatchSelection{input: RunBatchInput{APIVersion: "tplaiter.dev/run-batch-input/v1"}}
		for _, name := range names {
			b.input.Steps = append(b.input.Steps, BatchStep{Name: name, Parameters: json.RawMessage(`{}`)})
			b.originals = append(b.originals, batchHashOriginal(t, name))
		}
		if e := b.bind(); e != nil {
			t.Fatal(e)
		}
		return b
	}
	b := build([]string{"check", "check"})
	defer b.Close()
	if len(b.Operation().Actions) != 2 || b.selections[0].request.RequestSHA256 == b.selections[1].request.RequestSHA256 {
		t.Fatal("repeated command ordinal not bound")
	}
	if b.selections[0].request.OperationInputsSHA256 != b.selections[1].request.OperationInputsSHA256 {
		t.Fatal("not ONE operation")
	}
	for _, original := range b.originals {
		same := batchHashOriginal(t, original.request.Action.ID)
		if !reflect.DeepEqual(original.operation, same.operation) || !reflect.DeepEqual(original.request, same.request) || !bytes.Equal(original.capsule, same.capsule) || !reflect.DeepEqual(original.contentBytes, same.contentBytes) {
			t.Fatal("single action original mutated")
		}
	}
	repeat := build([]string{"check", "check"})
	defer repeat.Close()
	if !reflect.DeepEqual(b.Requests(), repeat.Requests()) {
		t.Fatal("nondeterministic")
	}
	ordered := build([]string{"check", "second"})
	defer ordered.Close()
	reordered := build([]string{"second", "check"})
	defer reordered.Close()
	if ordered.commitment == reordered.commitment || ordered.Requests()[0].OperationInputsSHA256 == reordered.Requests()[1].OperationInputsSHA256 {
		t.Fatal("order transplant accepted")
	}
	copied := b.Requests()
	copied[0].Action.Argv[0] = "mutated"
	if b.Requests()[0].Action.Argv[0] != "checker" {
		t.Fatal("detached request aliases")
	}
}
