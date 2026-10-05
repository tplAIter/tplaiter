package workspace

import (
	"context"
	"errors"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	physical "github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type Transaction struct {
	physical           *physical.Transaction
	workspace, service *trustload.Runtime
	renderer           string
}

func Begin(ctx context.Context, p *Plan, expected string) (*Transaction, error) {
	if p == nil || expected == "" || expected != p.Fingerprint() {
		return nil, physical.ErrAuthentication
	}
	fresh, err := Prepare(ctx, p.workspace, p.service, p.material.Home, p.renderer, p.input)
	if err != nil || !equal(fresh.material, p.material) {
		return nil, errors.Join(physical.ErrConflict, err)
	}
	engine, err := physical.Acquire(ctx, p.workspace, physical.NativeWorkspaceKind, p.material)
	if err != nil {
		return nil, err
	}
	t := &Transaction{physical: engine, workspace: p.workspace, service: p.service, renderer: p.renderer}
	fail := func(err error) (*Transaction, error) { t.Release(); return t, err }
	if err := engine.LeaseWorkspaceService(ctx, p.service); err != nil {
		return fail(err)
	}
	fresh, err = Prepare(ctx, p.workspace, p.service, p.material.Home, p.renderer, p.input)
	if err != nil {
		return fail(err)
	}
	if err := engine.ValidateLocked(ctx, fresh.material); err != nil {
		return fail(err)
	}
	if err := engine.Seal(ctx, fresh.material); err != nil {
		return fail(err)
	}
	return t, nil
}

func Open(ctx context.Context, wr, sr *trustload.Runtime, home, id, renderer string) (*Transaction, error) {
	engine, err := physical.Open(ctx, wr, physical.NativeWorkspaceKind, home, id)
	if err != nil {
		return nil, err
	}
	t := &Transaction{physical: engine, workspace: wr, service: sr, renderer: renderer}
	fail := func(err error) (*Transaction, error) { t.Release(); return nil, err }
	if err := engine.LeaseWorkspaceService(ctx, sr); err != nil {
		return fail(err)
	}
	if err := t.authenticate(ctx); err != nil {
		return fail(err)
	}
	if err := engine.Admit(ctx); err != nil {
		return fail(err)
	}
	return t, nil
}

func (t *Transaction) authenticate(ctx context.Context) error {
	if t == nil || t.physical == nil || t.service == nil || t.workspace == nil {
		return physical.ErrAuthentication
	}
	m, err := t.physical.CheckedMaterial()
	if err != nil {
		return err
	}
	var saved intent
	if err := canonicaljson.DecodeStrict(m.Intent, &saved); err != nil {
		return err
	}
	if saved.Renderer != t.renderer || !equal(saved.Service, t.service.ProjectContext()) || m.Registry == nil {
		return physical.ErrAuthentication
	}
	rebuilt, err := construct(ctx, t.workspace, t.service, m.Home, t.renderer, saved.Input, m.Before, m.Registry.Before)
	if err != nil {
		return err
	}
	if !equal(m, rebuilt) {
		return physical.ErrAuthentication
	}
	return nil
}

func (t *Transaction) ID() string {
	if t == nil || t.physical == nil {
		return ""
	}
	return t.physical.ID()
}

// Report returns service identity from the retained authenticated material.
func (t *Transaction) Report() (Report, error) {
	m, err := t.physical.CheckedMaterial()
	if err != nil {
		return Report{}, err
	}
	var saved intent
	if err := canonicaljson.DecodeStrict(m.Intent, &saved); err != nil {
		return Report{}, err
	}
	return (&Plan{material: m, input: saved.Input}).Report(), nil
}

func (t *Transaction) Release() {
	if t != nil && t.physical != nil {
		t.physical.Release()
	}
}

func (t *Transaction) Commit(ctx context.Context) error {
	if err := t.authenticate(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	if err := t.checkTerminal(ctx); err != nil {
		return err
	}
	return t.physical.Commit(ctx)
}

func (t *Transaction) Abort(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if err := t.checkTerminal(ctx); err != nil {
		return err
	}
	return t.physical.Rollback(ctx)
}

func (t *Transaction) checkTerminal(ctx context.Context) error {
	committed, err := t.physical.CheckWorkspaceTerminal(ctx, t.service)
	if err != nil || !committed {
		return err
	}
	_, err = stateledger.VerifyStable(ctx, t.service.ProjectContext().RootPath, t.service.TrustRuntime(), stateledger.StableVerifyOptions{})
	return err
}
