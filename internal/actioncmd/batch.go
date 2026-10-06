package actioncmd

import (
	"context"
	"errors"
	"sync"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// BatchResult is factual data only. Planned, attempted-without-fact and observed
// outcomes are distinguished; no decoder can recreate the BatchSession.
type BatchResult struct {
	APIVersion            string            `json:"apiVersion"`
	OperationInputsSHA256 string            `json:"operationInputsSHA256"`
	Disposition           string            `json:"disposition"`
	Steps                 []BatchStepResult `json:"steps"`
}
type BatchStepResult struct {
	Ordinal       int                        `json:"ordinal"`
	Name          string                     `json:"name"`
	RequestSHA256 string                     `json:"requestSHA256"`
	State         string                     `json:"state"`
	Receipt       *execx.ActionProcessResult `json:"receipt"`
}

// BatchSession owns one parent reader lifetime, all original ordinal
// observations and all children until the final connected writer releases it.
type BatchSession struct {
	mu        sync.Mutex
	owner     *trustload.Runtime
	selection *operationtrust.RunBatchSelection
	lease     *runtimeassembly.ReadSession
	runner    *execx.ApprovedRunner
	started   bool
	outcome   *BatchResult
}

func PrepareRunBatch(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, input operationtrust.RunBatchInput) (*BatchSession, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || source == nil {
		return nil, ErrSession
	}
	lease, e := runtimeassembly.OpenReadOnly(ctx, owner, runtimeassembly.Options{})
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			lease.Close()
		}
	}()
	selection, e := operationtrust.PrepareRunBatch(ctx, owner, source, input)
	if e != nil {
		return nil, e
	}
	defer func() {
		if !good {
			selection.Close()
		}
	}()
	runner, e := execx.NewApprovedRunner(owner)
	if e != nil {
		return nil, e
	}
	s := &BatchSession{owner: owner, selection: selection, lease: lease, runner: runner}
	if e = s.recheck(ctx); e != nil {
		return nil, e
	}
	good = true
	return s, nil
}

func (s *BatchSession) Requests() ([]trustverify.ExecutionRequest, error) {
	if s == nil {
		return nil, ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selection == nil || s.lease == nil {
		return nil, ErrSession
	}
	return s.selection.Requests(), nil
}

func (s *BatchSession) Recheck(ctx context.Context) error {
	if s == nil {
		return ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recheck(ctx)
}

func (s *BatchSession) recheck(ctx context.Context) error {
	if s == nil || s.owner == nil || s.selection == nil || s.lease == nil || ctx == nil {
		return ErrSession
	}
	if e := s.lease.Recheck(ctx); e != nil {
		return e
	}
	return s.selection.Recheck(ctx, s.owner)
}

// Execute validates the full approval vector before first spawn, then performs
// the same per-launch permit/source checks. Factual outcomes precede late error
// handling and are retained internally until the final emitter completes.
func (s *BatchSession) Execute(ctx context.Context, refs []trustverify.ApprovalRefs) (*BatchResult, error) {
	if s == nil {
		return nil, ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil, ErrSession
	}
	if e := s.recheck(ctx); e != nil {
		return nil, e
	}
	requests := s.selection.Requests()
	if e := execx.PreflightActionBatchControls(s.owner.ProjectContext().Key, s.selection.Input(), requests, refs); e != nil {
		return nil, e
	}
	// Consumer frame preflight is required before this method becomes a normal
	// registered route; the joined producer owns actual CLI/MCP wrapper encoding.
	permits, materials, e := operationtrust.AuthorizeRunBatch(ctx, s.owner, s.selection, refs)
	if e != nil {
		return nil, e
	}
	if e = s.recheck(ctx); e != nil {
		return nil, e
	}
	s.started = true
	result := &BatchResult{APIVersion: "tplaiter.dev/action-batch-receipt/v1", OperationInputsSHA256: requests[0].OperationInputsSHA256, Disposition: "completed", Steps: make([]BatchStepResult, len(requests))}
	input := s.selection.Input()
	for i, r := range requests {
		result.Steps[i] = BatchStepResult{Ordinal: i, Name: input.Steps[i].Name, RequestSHA256: r.RequestSHA256, State: "unstarted"}
	}
	s.outcome = result
	for i, request := range requests {
		if e = s.recheck(ctx); e != nil {
			result.Disposition = "recovery-required"
			return cloneBatchResult(result), e
		}
		result.Steps[i].State = "attempted-unknown"
		receipt, runError := s.runner.ExecuteAction(ctx, permits[i], request, materials[i])
		if receipt != nil {
			factual, projectionError := receipt.ResultFor(s.runner, request)
			if projectionError == nil {
				result.Steps[i].Receipt = &factual
				result.Steps[i].State = "observed"
			}
			runError = errors.Join(runError, projectionError)
		}
		final := s.recheck(ctx)
		if e = errors.Join(runError, final); e != nil {
			result.Disposition = "recovery-required"
			return cloneBatchResult(result), e
		}
		fact := result.Steps[i].Receipt
		if fact == nil {
			result.Disposition = "recovery-required"
			return cloneBatchResult(result), ErrSession
		}
		if fact.ChildExitCode == nil || *fact.ChildExitCode != 0 || fact.Signal != 0 || !fact.OutputComplete || fact.Overflow || fact.Cancelled || fact.TimedOut {
			result.Disposition = "stopped"
			return cloneBatchResult(result), nil
		}
	}
	return cloneBatchResult(result), nil
}

func (s *BatchSession) EnterBootstrap(ctx context.Context, control execx.ActionBootstrapControl) error {
	if s == nil {
		return ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || control.APIVersion != "tplaiter.dev/action-bootstrap/v2" || control.Ordinal == nil {
		return ErrSession
	}
	if e := s.recheck(ctx); e != nil {
		return e
	}
	requests := s.selection.Requests()
	i := *control.Ordinal
	if i < 0 || i >= len(requests) || control.RequestSHA256 != requests[i].RequestSHA256 || len(control.Approvals) != len(requests) {
		return ErrSession
	}
	refs := make([]trustverify.ApprovalRefs, len(requests))
	for j, cas := range control.Approvals {
		refs[j] = trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: cas}
	}
	if e := execx.PreflightActionBatchControls(s.owner.ProjectContext().Key, s.selection.Input(), requests, refs); e != nil {
		return e
	}
	permits, materials, e := operationtrust.AuthorizeRunBatch(ctx, s.owner, s.selection, refs)
	if e != nil {
		return e
	}
	if e = s.recheck(ctx); e != nil {
		return e
	}
	s.started = true
	s.lease.Close()
	s.lease = nil
	return s.runner.EnterActionBootstrap(ctx, permits[i], requests[i], materials[i], control)
}

func (s *BatchSession) Outcome() *BatchResult {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneBatchResult(s.outcome)
}

func (s *BatchSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selection != nil {
		s.selection.Close()
		s.selection = nil
	}
	if s.lease != nil {
		s.lease.Close()
		s.lease = nil
	}
	s.runner = nil
	s.owner = nil
}

func cloneBatchResult(in *BatchResult) *BatchResult {
	if in == nil {
		return nil
	}
	out := *in
	out.Steps = append([]BatchStepResult(nil), in.Steps...)
	for i, step := range out.Steps {
		if step.Receipt != nil {
			r := *step.Receipt
			r.Stdout = append([]byte{}, r.Stdout...)
			r.Stderr = append([]byte{}, r.Stderr...)
			if r.ChildExitCode != nil {
				v := *r.ChildExitCode
				r.ChildExitCode = &v
			}
			if r.PersistentWrites != nil {
				v := *r.PersistentWrites
				r.PersistentWrites = &v
			}
			out.Steps[i].Receipt = &r
		}
	}
	return &out
}
