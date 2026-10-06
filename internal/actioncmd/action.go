// Package actioncmd connects one authenticated declaration to the existing
// approval/runner. It owns the read lease through the caller's final emission.
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

var ErrSession = errors.New("TRUST_ACTION_SESSION_UNAVAILABLE")

// Session has no decoder or public grant constructor. The installed command
// creates it with a real runtime and resolution; neither Request nor Result
// can be deserialized back into this operation lifetime.
type Session struct {
	mu        sync.Mutex
	owner     *trustload.Runtime
	source    *trustverify.VerifiedResolution
	selection *operationtrust.ActionSelection
	lease     *runtimeassembly.ReadSession
	material  *operationtrust.ExecutionMaterial
	runner    *execx.ApprovedRunner
	started   bool
}

func Prepare(ctx context.Context, r *trustload.Runtime, source *trustverify.VerifiedResolution, input operationtrust.ActionInput) (*Session, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.TrustRuntime() == nil || source == nil {
		return nil, ErrSession
	}
	lease, e := runtimeassembly.OpenReadOnly(ctx, r, runtimeassembly.Options{})
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			lease.Close()
		}
	}()
	tool, e := operationtrust.ResolveActionTool(ctx, r, source, input.Name)
	if e != nil {
		return nil, e
	}
	selection, e := operationtrust.PrepareAction(ctx, r, source, tool, input)
	if e != nil {
		return nil, e
	}
	defer func() {
		if !success {
			selection.Close()
		}
	}()
	material, e := operationtrust.BindActionMaterial(ctx, r, selection)
	if e != nil {
		return nil, e
	}
	runner, e := execx.NewApprovedRunner(r)
	if e != nil {
		return nil, e
	}
	s := &Session{owner: r, source: source, selection: selection, lease: lease, material: material, runner: runner}
	if e = s.recheck(ctx); e != nil {
		return nil, e
	}
	success = true
	return s, nil
}

func (s *Session) Request() (trustverify.ExecutionRequest, error) {
	if s == nil {
		return trustverify.ExecutionRequest{}, ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selection == nil || s.lease == nil {
		return trustverify.ExecutionRequest{}, ErrSession
	}
	return s.selection.Request(), nil
}

func (s *Session) Recheck(ctx context.Context) error {
	if s == nil {
		return ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recheck(ctx)
}

func (s *Session) recheck(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.owner == nil || s.selection == nil || s.lease == nil {
		return ErrSession
	}
	if e := s.lease.Recheck(ctx); e != nil {
		return e
	}
	return s.selection.Recheck(ctx, s.owner)
}

// Execute accepts only persistent signed approval references, never a reader,
// binary, path, callback, serialized permit or Boolean authorization decision.
// It returns already observed factual outcome alongside any late failure.
func (s *Session) Execute(ctx context.Context, refs trustverify.ApprovalRefs) (*execx.ActionProcessResult, error) {
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
	request := s.selection.Request()
	permits, e := operationtrust.AuthorizeActions(ctx, s.owner.TrustRuntime(), s.source, s.selection.Operation(), []trustverify.ExecutionRequest{request}, []trustverify.ApprovalRefs{refs})
	if e != nil {
		return nil, e
	}
	if e = s.recheck(ctx); e != nil {
		return nil, e
	}
	s.started = true
	receipt, e := s.runner.ExecuteAction(ctx, permits[0], request, s.material)
	if receipt == nil {
		return nil, e
	}
	result, projectionError := receipt.ResultFor(s.runner, request)
	if projectionError != nil {
		return nil, errors.Join(e, projectionError)
	}
	if check := s.recheck(ctx); check != nil {
		result.Disposition = "recovery-required"
		e = errors.Join(e, check)
	}
	return &result, e
}

// EnterBootstrap reconstructs the exact approval in the child before kernel
// confinement. Parent Session retains the original source/writer lease. No
// action authority is taken from the control message or any receipt body.
func (s *Session) EnterBootstrap(ctx context.Context, control execx.ActionBootstrapControl) error {
	if s == nil {
		return ErrSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return ErrSession
	}
	if e := s.recheck(ctx); e != nil {
		return e
	}
	request := s.selection.Request()
	if request.RequestSHA256 != control.RequestSHA256 {
		return ErrSession
	}
	refs := trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: control.ApprovalCAS}
	permits, e := operationtrust.AuthorizeActions(ctx, s.owner.TrustRuntime(), s.source, s.selection.Operation(), []trustverify.ExecutionRequest{request}, []trustverify.ApprovalRefs{refs})
	if e != nil {
		return e
	}
	if e = s.recheck(ctx); e != nil {
		return e
	}
	s.started = true
	// Child reader descriptors must not leak into the native tool. Original
	// parent holds stay live through Wait and complete final output.
	s.lease.Close()
	s.lease = nil
	return s.runner.EnterActionBootstrap(ctx, permits[0], request, s.material, control)
}

func (s *Session) Close() {
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
	s.material = nil
	s.runner = nil
	s.owner = nil
	s.source = nil
}
