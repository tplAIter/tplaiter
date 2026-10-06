package blockformatter

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// AuthorizedPasses owns the per-ordinal consumption of a managed pair.
// Durable started/completed state belongs to the formatter evidence owner.
type AuthorizedPasses struct {
	mu       sync.Mutex
	adapter  *RuntimeAdapter
	prepared *PreparedFormat
	permits  []*trustverify.ExecutionPermit
	used     [2]bool
}
type CompletedPass struct {
	adapter             *RuntimeAdapter
	prepared            *PreparedFormat
	receipt             *execx.ExecutionReceipt
	ordinal             int
	observation         *trustverify.PersistentObservation
	reference           trustverify.PersistentApprovalReference
	observed, completed time.Time
}

// PassData is transport only; it cannot construct CompletedPass or a permit.
type PassData struct {
	Ordinal     int                                     `json:"ordinal"`
	Operation   trustverify.OperationInputs             `json:"operation"`
	Request     trustverify.ExecutionRequest            `json:"request"`
	Approval    trustverify.PersistentApprovalReference `json:"approval"`
	ObservedAt  time.Time                               `json:"observedAt"`
	CompletedAt time.Time                               `json:"completedAt"`
	Plan        Plan                                    `json:"plan"`
	Input       []byte                                  `json:"input"`
	Output      []byte                                  `json:"output"`
	Context     []byte                                  `json:"context"`
}

func (a *RuntimeAdapter) AuthorizePasses(ctx context.Context, p *PreparedFormat, refs []trustverify.ApprovalRefs) (*AuthorizedPasses, error) {
	if len(refs) != 2 {
		return nil, ErrRuntimeUnavailable
	}
	return a.AuthorizeSelectedPasses(ctx, p, map[int]trustverify.ApprovalRefs{1: refs[0], 2: refs[1]})
}

// AuthorizeSelectedPasses still obtains real fresh native permits for every
// selected request. Selection is not authority; an absent permit cannot run.
// The retained-effects owner selects only genuinely missing ordinals, so a
// completed historical effect never causes a new spawn grant to be issued.
func (a *RuntimeAdapter) AuthorizeSelectedPasses(ctx context.Context, p *PreparedFormat, refs map[int]trustverify.ApprovalRefs) (*AuthorizedPasses, error) {
	if a == nil || a.runtime == nil || a.runtime.TrustRuntime() != a.stable || p == nil || p.selection.adapter != a || len(p.selection.context) == 0 || len(p.requests) != 2 || len(refs) == 0 || len(refs) > 2 || ctx == nil || ctx.Err() != nil {
		return nil, ErrRuntimeUnavailable
	}
	if p.selection.updateCalculation != nil {
		if err := p.selection.updateCalculation.RecheckFor(ctx, a.runtime); err != nil {
			return nil, err
		}
	}
	if p.selection.sources != nil {
		if err := p.selection.sources.RecheckFor(ctx, a.runtime); err != nil {
			return nil, err
		}
	}
	for ordinal := range refs {
		if ordinal < 1 || ordinal > 2 {
			return nil, ErrRuntimeUnavailable
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return nil, ErrRuntimeUnavailable
	}
	p.used = true
	out := &AuthorizedPasses{adapter: a, prepared: p, permits: make([]*trustverify.ExecutionPermit, 2)}
	for i, request := range p.requests {
		ref, selected := refs[i+1]
		if !selected {
			continue
		}
		permit, err := a.stable.Authorize(ctx, p.selection.provider, p.operation, request, ref)
		if err != nil {
			return nil, err
		}
		if _, err = a.stable.PersistentApprovalReference(permit); err != nil {
			return nil, err
		}
		out.permits[i] = permit
	}
	return out, nil
}

func (a *RuntimeAdapter) RunPass(ctx context.Context, p *AuthorizedPasses, ordinal int) (*CompletedPass, error) {
	if a == nil || p == nil || p.adapter != a || ordinal < 1 || ordinal > 2 || ctx == nil || ctx.Err() != nil {
		return nil, ErrRuntimeUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := ordinal - 1
	if p.used[i] || p.permits[i] == nil || a.runtime.TrustRuntime() != a.stable {
		return nil, ErrRuntimeUnavailable
	}
	p.used[i] = true
	observation, err := a.stable.PersistentApprovalObservation(p.permits[i])
	if err != nil {
		return nil, err
	}
	receipt, err := a.runner.Execute(ctx, p.permits[i], p.prepared.requests[i], p.prepared.materials[i])
	if err != nil {
		return nil, err
	}
	if _, err = receipt.StdoutFor(a.runner, p.prepared.requests[i]); err != nil {
		return nil, err
	}
	ref, start, end, err := observation.CompleteFor(a.stable)
	if err != nil {
		return nil, err
	}
	return &CompletedPass{adapter: a, prepared: p.prepared, receipt: receipt, ordinal: ordinal, observation: observation, reference: ref, observed: start, completed: end}, nil
}

func (p *CompletedPass) DataFor(r *trustload.Runtime) (PassData, error) {
	if p == nil || r == nil || p.adapter == nil || p.adapter.runtime != r || r.TrustRuntime() != p.adapter.stable || p.ordinal < 1 || p.ordinal > 2 {
		return PassData{}, ErrRuntimeUnavailable
	}
	req := cloneRequests(p.prepared.requests)[p.ordinal-1]
	output, err := p.receipt.StdoutFor(p.adapter.runner, req)
	if err != nil {
		return PassData{}, err
	}
	ref, start, end := p.reference, p.observed, p.completed
	return PassData{Ordinal: p.ordinal, Operation: cloneOperation(p.prepared.operation), Request: req, Approval: ref, ObservedAt: start, CompletedAt: end, Plan: clonePlan(p.prepared.selection.plan), Input: append([]byte(nil), p.prepared.selection.input...), Output: output, Context: append([]byte(nil), p.prepared.selection.context...)}, nil
}

// CheckRetainedPair performs pure syntax/order and same-input validation.
// It does not authenticate transport records or grant publication authority.
func CheckRetainedPair(a, b PassData) (Check, error) {
	if a.Ordinal != 1 || b.Ordinal != 2 || a.Request.RequestSHA256 == b.Request.RequestSHA256 || a.Request.Action.ID == b.Request.Action.ID || a.Request.Tool != b.Request.Tool || a.Request.EnvironmentPolicySHA256 != b.Request.EnvironmentPolicySHA256 {
		return Check{}, ErrRuntimeUnavailable
	}
	if err := operationtrust.ValidateRetainedFormatterContext(a.Context, a.Operation.Scope); err != nil {
		return Check{}, err
	}
	if !equalPassMaterial(a, b) {
		return Check{}, ErrRuntimeUnavailable
	}
	return CheckOutputs(a.Plan, a.Input, a.Output, b.Output, markerValidator{})
}

func equalPassMaterial(a, b PassData) bool {
	return bytes.Equal(a.Input, b.Input) && bytes.Equal(a.Context, b.Context) && reflect.DeepEqual(a.Plan, b.Plan) && reflect.DeepEqual(a.Operation, b.Operation) && a.Request.OperationInputsSHA256 == b.Request.OperationInputsSHA256 && a.Request.Action.ContentClosureSHA256 == b.Request.Action.ContentClosureSHA256 && a.Request.TimeoutMillis == b.Request.TimeoutMillis && reflect.DeepEqual(a.Request.Action.Argv, b.Request.Action.Argv) && a.Request.WorkingDirectoryScope == b.Request.WorkingDirectoryScope
}
