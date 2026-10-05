package projecttransaction

import (
	"context"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

// ErrUpdatePreparingContinue is retained for compatibility with callers of the
// former preparing refusal. Authenticated prefixes now resume; ambiguous staging
// and receipt/ownership failures remain transaction errors, not this sentinel.
var ErrUpdatePreparingContinue = engine.ErrPreparingContinue

// UpdateTransaction cannot be constructed with arbitrary material, callbacks or
// a signing key. Only fresh signed Plan admission or authenticated cold recovery
// can obtain an admitted mutable handle.
type UpdateTransaction struct {
	physical        *engine.Transaction
	runtime         *trustload.Runtime
	rendererVersion string
}

// BeginUpdate validates concrete signed preparation before AND after actual
// engine leases, verifies the held control image, and durably seals the exact
// project and registry mutation images.
func BeginUpdate(ctx context.Context, p *updateplan.Plan, expected string) (*UpdateTransaction, error) {
	initial, r, err := p.TransactionMaterial(ctx, expected)
	if err != nil {
		return nil, err
	}
	draft, err := updateEngineMaterial(initial)
	if err != nil {
		return nil, err
	}
	physical, err := engine.Acquire(ctx, r, engine.NativeUpdateKind, draft)
	if err != nil {
		return nil, err
	}
	t := &UpdateTransaction{physical: physical, runtime: r, rendererVersion: initial.RendererVersion}
	fail := func(err error) (*UpdateTransaction, error) { t.Release(); return t, err }
	fresh, _, err := p.TransactionMaterialAfterLease(ctx, expected)
	if err != nil {
		return fail(err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, r, fresh.RendererVersion, fresh); err != nil {
		return fail(err)
	}
	m, err := updateEngineMaterial(fresh)
	if err != nil {
		return fail(err)
	}
	if err := physical.ValidateLocked(ctx, m); err != nil {
		return fail(err)
	}
	var sealErr error
	if fresh.Version == 2 {
		scope, e := engine.ScopeAdoption(ctx, physical)
		if e != nil {
			return fail(e)
		}
		sealErr = scope.Seal(ctx, m)
	} else {
		sealErr = physical.Seal(ctx, m)
	}
	if err := sealErr; err != nil {
		return fail(err)
	}
	return t, nil
}

// OpenUpdate authenticates the kind-bound receipt, actual engine lease/root and
// fresh source/target semantics before phase-aware engine admission. Receipt
// data alone cannot authorize recovery.
func OpenUpdate(ctx context.Context, r *trustload.Runtime, home, id, actualRendererVersion string) (*UpdateTransaction, error) {
	physical, err := engine.Open(ctx, r, engine.NativeUpdateKind, home, id)
	if err != nil {
		return nil, err
	}
	t := &UpdateTransaction{physical: physical, runtime: r, rendererVersion: actualRendererVersion}
	if err := t.authenticateUpdate(ctx); err != nil {
		t.Release()
		return nil, err
	}
	var admitErr error
	checked, e := physical.CheckedMaterial()
	if e != nil {
		t.Release()
		return nil, e
	}
	var intent updateplan.UpdateMaterial
	if e = canonicaljson.DecodeStrict(checked.Intent, &intent); e != nil {
		t.Release()
		return nil, e
	}
	if intent.Version == 2 {
		scope, e := engine.ScopeAdoption(ctx, physical)
		if e != nil {
			t.Release()
			return nil, e
		}
		admitErr = scope.Admit(ctx)
	} else {
		admitErr = physical.Admit(ctx)
	}
	if err := admitErr; err != nil {
		t.Release()
		return nil, err
	}
	return t, nil
}

func (t *UpdateTransaction) authenticateUpdate(ctx context.Context) error {
	if t == nil || t.physical == nil || t.runtime == nil {
		return ErrAuthentication
	}
	m, materialErr := t.physical.CheckedMaterial()
	if materialErr != nil {
		return fmt.Errorf("update receipt transport: %w", materialErr)
	}
	var intent updateplan.UpdateMaterial
	if err := canonicaljson.DecodeStrict(m.Intent, &intent); err != nil {
		return fmt.Errorf("update intent decode: %w", err)
	}
	if err := updateplan.AuthenticateUpdateMaterial(ctx, t.runtime, t.rendererVersion, intent); err != nil {
		return err
	}
	expected, err := updateEngineMaterial(intent)
	if err != nil {
		return err
	}
	a, err := canonicaljson.Canonical(m)
	if err != nil {
		return err
	}
	b, err := canonicaljson.Canonical(expected)
	if err != nil || string(a) != string(b) {
		return ErrAuthentication
	}
	return nil
}

func updateEngineMaterial(m updateplan.UpdateMaterial) (engine.Material, error) {
	raw, err := canonicaljson.Canonical(m)
	if err != nil {
		return engine.Material{}, err
	}
	convert := func(in map[string]updateplan.UpdateFile) map[string]engine.File {
		out := map[string]engine.File{}
		for p, f := range in {
			out[p] = engine.File{Data: append(engine.Bytes{}, f.Data...), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
		}
		return out
	}
	// Registry remains explicitly in signed intent, not disguised as a project
	// path or silently omitted from transaction commit semantics.
	pair := &engine.RegistryPair{Before: engine.File{Data: append(engine.Bytes{}, m.Registry.BeforeContent...), Mode: m.Registry.Before.Mode, Device: m.RegistryDevice, Inode: m.RegistryInode}, After: engine.File{Data: append(engine.Bytes{}, m.Registry.AfterContent...), Mode: m.Registry.After.Mode}}
	return engine.Material{Registry: pair, Root: m.Root, Home: m.Home, ProjectID: m.ProjectID, Binding: m.Binding, Before: convert(m.Before), After: convert(m.After), Fingerprint: m.Fingerprint, ReadOnlyPaths: updateReadOnlyPaths(m), Intent: raw}, nil
}

func (t *UpdateTransaction) ID() string {
	if t == nil || t.physical == nil {
		return ""
	}
	return t.physical.ID()
}

func (t *UpdateTransaction) Release() {
	if t != nil && t.physical != nil {
		t.physical.Release()
	}
}

func (t *UpdateTransaction) Apply(ctx context.Context) error {
	if err := t.authenticateUpdate(ctx); err != nil {
		return err
	}
	if scope, e := t.adoptionScope(ctx); e != nil {
		return e
	} else if scope != nil {
		return scope.Apply(ctx)
	}
	return t.physical.Apply(ctx)
}

func (t *UpdateTransaction) Commit(ctx context.Context) error {
	// Reauthenticate even on cancellation so the engine can conditionally restore
	// owned publication images; the original context still controls Commit.
	if err := t.authenticateUpdate(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	if scope, e := t.adoptionScope(ctx); e != nil {
		return e
	} else if scope != nil {
		return scope.Commit(ctx)
	}
	return t.physical.Commit(ctx)
}

func (t *UpdateTransaction) Rollback(ctx context.Context) error {
	if err := t.authenticateUpdate(ctx); err != nil {
		return err
	}
	if scope, e := t.adoptionScope(ctx); e != nil {
		return e
	} else if scope != nil {
		return scope.Rollback(ctx)
	}
	return t.physical.Rollback(ctx)
}

// ApplyUpdate is the concrete composition-root operation; updateplan deliberately
// never imports this facade or substitutes a generic writer callback.
func ApplyUpdate(ctx context.Context, p *updateplan.Plan, expected string) error {
	t, err := BeginUpdate(ctx, p, expected)
	if err != nil {
		return err
	}
	defer t.Release()
	return t.Commit(ctx)
}

func updateReadOnlyPaths(m updateplan.UpdateMaterial) []string {
	out := []string{}
	if m.Protection != nil {
		for _, p := range m.Protection.Paths {
			if p.Observation.Exists {
				out = append(out, p.Path)
			}
		}
	}
	return out
}
func (t *UpdateTransaction) adoptionScope(ctx context.Context) (*engine.AdoptionTransaction, error) {
	m, err := t.physical.CheckedMaterial()
	if err != nil {
		return nil, err
	}
	var in updateplan.UpdateMaterial
	if err = canonicaljson.DecodeStrict(m.Intent, &in); err != nil {
		return nil, err
	}
	if in.Version == 1 {
		return nil, nil
	}
	return engine.ScopeAdoption(ctx, t.physical)
}
