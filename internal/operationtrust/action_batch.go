package operationtrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	MaxRunBatchSteps = 16
	MaxRunBatchFrame = 1 << 20
	MaxRunBatchInput = 8 << 10
)

var ErrRunBatch = errors.New("TRUST_ACTION_BATCH_INVALID")

// BatchStep is closed selection transport. It carries no approval or capability.
type BatchStep struct {
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters"`
}
type RunBatchInput struct {
	APIVersion string      `json:"apiVersion"`
	Steps      []BatchStep `json:"steps"`
}

func DecodeRunBatchInput(raw []byte) (RunBatchInput, error) {
	var in RunBatchInput
	if len(raw) == 0 || len(raw) > MaxRunBatchInput || canonicaljson.DecodeStrict(raw, &in) != nil || in.APIVersion != "tplaiter.dev/run-batch-input/v1" || len(in.Steps) < 1 || len(in.Steps) > MaxRunBatchSteps {
		return in, ErrRunBatch
	}
	for _, s := range in.Steps {
		var p map[string]json.RawMessage
		if !actionToken(s.Name) || canonicaljson.DecodeStrict(s.Parameters, &p) != nil || p == nil || len(p) > 16 {
			return in, ErrRunBatch
		}
	}
	return in, nil
}

// RunBatchSelection owns original observations for the entire ordered operation.
// No public constructor accepts requests, detached snapshots or caller digests.
type RunBatchSelection struct {
	owner      *trustload.Runtime
	source     *trustverify.VerifiedResolution
	input      RunBatchInput
	originals  []*ActionSelection
	selections []*batchActionSelection
	operation  trustverify.OperationInputs
	commitment string
	closed     bool
}

func PrepareRunBatch(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, in RunBatchInput) (*RunBatchSelection, error) {
	raw, e := canonicaljson.Canonical(in)
	if e != nil {
		return nil, e
	}
	in, e = DecodeRunBatchInput(raw)
	if e != nil {
		return nil, e
	}
	b := &RunBatchSelection{owner: owner, source: source, input: in}
	success := false
	defer func() {
		if !success {
			b.Close()
		}
	}()
	for _, step := range in.Steps {
		tool, e := ResolveActionTool(ctx, owner, source, step.Name)
		if e != nil {
			return nil, e
		}
		s, e := PrepareAction(ctx, owner, source, tool, ActionInput{Name: step.Name, ParametersJSON: step.Parameters})
		if e != nil {
			return nil, e
		}
		b.originals = append(b.originals, s)
	}
	if e = b.bind(); e != nil {
		return nil, e
	}
	success = true
	return b, nil
}

func (b *RunBatchSelection) bind() error {
	if len(b.originals) < 1 || len(b.originals) > MaxRunBatchSteps {
		return ErrRunBatch
	}
	// The commitment precedes capsules and operation hashing, avoiding a circular
	// hash. It binds every original request, order, typed parameters and preimage.
	originals := make([]trustverify.ExecutionRequest, len(b.originals))
	for i, s := range b.originals {
		originals[i] = s.Request()
	}
	raw, e := canonicaljson.Canonical(struct {
		Domain   string                         `json:"domain"`
		Input    RunBatchInput                  `json:"input"`
		Requests []trustverify.ExecutionRequest `json:"requests"`
	}{"tplaiter.dev/run-batch-intent/v1", b.input, originals})
	if e != nil {
		return e
	}
	b.commitment = evidencecas.Digest(raw)
	op := cloneOperation(b.originals[0].operation)
	op.Actions = nil
	op.Subjects = nil
	subjectMap := map[string]trustverify.Provider{}
	preimages := make([]string, len(b.originals))
	for i, s := range b.originals {
		finalized := &batchActionSelection{batch: b, ordinal: i, original: s, content: append([]trustverify.ContentEntry(nil), s.content...), contentBytes: make([][]byte, len(s.contentBytes))}
		for j, body := range s.contentBytes {
			finalized.contentBytes[j] = append([]byte(nil), body...)
		}
		if s.operation.ProfileBindingSHA256 != op.ProfileBindingSHA256 || s.operation.ProjectID != op.ProjectID || s.operation.Scope != "run" || s.operation.AnswersSHA256 != op.AnswersSHA256 {
			return ErrRunBatch
		}
		preimages[i] = s.operation.PreimageSHA256
		for _, p := range s.operation.Subjects {
			subjectMap[providerKey(p)] = p
		}
		capsule, e := canonicaljson.Canonical(struct {
			APIVersion  string          `json:"apiVersion"`
			BatchSHA256 string          `json:"batchSHA256"`
			Ordinal     int             `json:"ordinal"`
			Steps       int             `json:"steps"`
			Action      json.RawMessage `json:"action"`
		}{"tplaiter.dev/action-batch-capsule/v1", b.commitment, i, len(b.originals), s.capsule})
		if e != nil || len(capsule) > actionMetadataLimit {
			return ErrRunBatch
		}
		finalized.capsule = capsule
		found := false
		for j, entry := range finalized.content {
			if entry.Root == "provider" && entry.Path == actionCapsulePath {
				finalized.content[j].ContentSHA256 = evidencecas.Digest(capsule)
				finalized.contentBytes[j] = append([]byte(nil), capsule...)
				found = true
			}
		}
		if !found {
			return ErrRunBatch
		}
		closure, e := trustverify.ComputeContentClosureSHA256(finalized.content)
		if e != nil {
			return e
		}
		a := s.operation.Actions[0]
		a.Action.ContentClosureSHA256 = closure
		op.Actions = append(op.Actions, a)
		finalized.request = cloneRequest(s.request)
		b.selections = append(b.selections, finalized)
	}
	for _, p := range subjectMap {
		op.Subjects = append(op.Subjects, p)
	}
	sort.Slice(op.Subjects, func(i, j int) bool { return providerKey(op.Subjects[i]) < providerKey(op.Subjects[j]) })
	pre, e := canonicaljson.Canonical(struct {
		Domain    string   `json:"domain"`
		Preimages []string `json:"preimages"`
	}{"tplaiter.dev/run-batch-preimages/v1", preimages})
	if e != nil {
		return e
	}
	op.PreimageSHA256 = evidencecas.Digest(pre)
	digest, e := trustverify.ComputeOperationInputsSHA256(op)
	if e != nil {
		return e
	}
	b.operation = op
	for i, s := range b.selections {
		s.request.Action = op.Actions[i].Action
		s.request.OperationInputsSHA256 = digest
		s.request.RequestSHA256, e = s.request.ComputeRequestSHA256()
		if e != nil {
			return e
		}
	}
	return nil
}

func (b *RunBatchSelection) Requests() []trustverify.ExecutionRequest {
	if b == nil || b.closed {
		return nil
	}
	out := make([]trustverify.ExecutionRequest, len(b.selections))
	for i, s := range b.selections {
		out[i] = cloneRequest(s.request)
	}
	return out
}

func (b *RunBatchSelection) Operation() trustverify.OperationInputs {
	if b == nil || b.closed {
		return trustverify.OperationInputs{}
	}
	return cloneOperation(b.operation)
}

func (b *RunBatchSelection) Input() RunBatchInput {
	if b == nil || b.closed {
		return RunBatchInput{}
	}
	raw, _ := canonicaljson.Canonical(b.input)
	var out RunBatchInput
	_ = json.Unmarshal(raw, &out)
	return out
}

func (b *RunBatchSelection) Material(ctx context.Context, owner *trustload.Runtime, ordinal int) (*ExecutionMaterial, error) {
	if b == nil || b.closed || b.owner != owner || ordinal < 0 || ordinal >= len(b.selections) {
		return nil, ErrRunBatch
	}
	if e := b.Recheck(ctx, owner); e != nil {
		return nil, e
	}
	return &ExecutionMaterial{batchAction: b.selections[ordinal]}, nil
}

func (b *RunBatchSelection) Recheck(ctx context.Context, owner *trustload.Runtime) error {
	if b == nil || b.closed || owner == nil || b.owner != owner || b.source == nil {
		return ErrRunBatch
	}
	for _, s := range b.originals {
		if e := s.checkObserved(ctx); e != nil {
			return e
		}
	}
	fresh, e := PrepareRunBatch(ctx, owner, b.source, b.input)
	if e != nil {
		return e
	}
	defer fresh.Close()
	if !reflect.DeepEqual(b.operation, fresh.operation) || b.commitment != fresh.commitment || len(b.selections) != len(fresh.selections) {
		return ErrRunBatch
	}
	for i, s := range b.selections {
		f := fresh.selections[i]
		if !reflect.DeepEqual(s.request, f.request) || !bytes.Equal(s.capsule, f.capsule) || !bytes.Equal(s.original.tool, f.original.tool) || !reflect.DeepEqual(s.contentBytes, f.contentBytes) {
			return ErrRunBatch
		}
		if e := s.original.checkObserved(ctx); e != nil {
			return e
		}
	}
	return nil
}

func (b *RunBatchSelection) Close() {
	if b == nil || b.closed {
		return
	}
	b.closed = true
	for _, s := range b.originals {
		s.Close()
	}
}

// Finalized ordinal material is separate from each immutable single-action
// preparation. Its original observations remain owned by the batch lifetime.
type batchActionSelection struct {
	batch        *RunBatchSelection
	ordinal      int
	original     *ActionSelection
	request      trustverify.ExecutionRequest
	capsule      []byte
	content      []trustverify.ContentEntry
	contentBytes [][]byte
}

func (s *batchActionSelection) staged(ctx context.Context, owner *trustload.Runtime, request trustverify.ExecutionRequest) (trustverify.StagedMaterial, ActionProjection, error) {
	if s == nil || s.batch == nil || s.batch.closed || s.batch.owner != owner || !reflect.DeepEqual(s.request, request) {
		return trustverify.StagedMaterial{}, ActionProjection{}, ErrRunBatch
	}
	if e := s.batch.Recheck(ctx, owner); e != nil {
		return trustverify.StagedMaterial{}, ActionProjection{}, e
	}
	o := s.original
	p := o.projection
	p.Stdin = append([]byte(nil), p.Stdin...)
	p.Files = append([]ActionInputFile(nil), p.Files...)
	for i := range p.Files {
		p.Files[i].Bytes = append([]byte(nil), p.Files[i].Bytes...)
	}
	data := make([][]byte, len(s.contentBytes))
	for i, b := range s.contentBytes {
		data[i] = append([]byte(nil), b...)
	}
	return trustverify.StagedMaterial{Operation: s.batch.Operation(), Request: cloneRequest(s.request), Content: append([]trustverify.ContentEntry(nil), s.content...), ContentBytes: data, ToolBytes: append([]byte(nil), o.tool...), ToolOptions: nativeActionToolOptions(request.Action.Argv), Environment: fixedEnvironment()}, p, nil
}

// AuthorizeRunBatch validates the entire matching vector before producing any
// ordinal material. References remain selection data, not serialized permits.
func AuthorizeRunBatch(ctx context.Context, owner *trustload.Runtime, b *RunBatchSelection, refs []trustverify.ApprovalRefs) ([]*trustverify.ExecutionPermit, []*ExecutionMaterial, error) {
	if b == nil || b.closed || b.owner != owner || len(refs) != len(b.selections) {
		return nil, nil, ErrRunBatch
	}
	if e := b.Recheck(ctx, owner); e != nil {
		return nil, nil, e
	}
	permits, e := AuthorizeActions(ctx, owner.TrustRuntime(), b.source, b.Operation(), b.Requests(), refs)
	if e != nil {
		return nil, nil, e
	}
	if e = b.Recheck(ctx, owner); e != nil {
		return nil, nil, e
	}
	approvals := make([]string, len(refs))
	for i, ref := range refs {
		if ref.Kind != "persistent-signed" {
			return nil, nil, ErrRunBatch
		}
		approvals[i] = ref.ApprovalCAS
	}
	materials := make([]*ExecutionMaterial, len(refs))
	for i := range materials {
		materials[i] = &ExecutionMaterial{batchAction: b.selections[i], batchApprovals: append([]string(nil), approvals...)}
	}
	return permits, materials, nil
}
