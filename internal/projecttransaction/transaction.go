// Package projecttransaction admits concrete authenticated operations into the
// neutral existing-tree engine. Transport and reports never grant write authority.
package projecttransaction

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const (
	APIVersion = engine.APIVersion
	Kind       = engine.NativeGeneratorKind
)

var (
	ErrConflict       = engine.ErrConflict
	ErrAuthentication = engine.ErrAuthentication
	ErrActive         = engine.ErrActive
)

// Transaction has no public material setter or injected authority callback.
// Only concrete native admission can obtain the private engine handle.
type Transaction struct {
	physical *engine.Transaction
	runtime  *trustload.Runtime
}

func (t *Transaction) ID() string { return t.physical.ID() }
func (t *Transaction) Release() {
	if t != nil && t.physical != nil {
		t.physical.Release()
	}
}

func BeginNative(ctx context.Context, p *gen.NativePlan) (*Transaction, error) {
	old, r, err := p.TransactionMaterial(ctx)
	if err != nil {
		return nil, err
	}
	draft, err := nativeEngineMaterial(old)
	if err != nil {
		return nil, err
	}
	physical, err := engine.Acquire(ctx, r, engine.NativeGeneratorKind, draft)
	if err != nil {
		return nil, err
	}
	t := &Transaction{physical: physical, runtime: r}
	fail := func(err error) (*Transaction, error) { t.Release(); return t, err }
	// This rechecks the actual opaque plan AFTER all real writer locks exist.
	// The engine additionally proves its held update-lock inode against the only
	// permitted added observation. No broad journal/control-directory exclusion.
	fresh, _, err := p.TransactionMaterialAfterLease(ctx)
	if err != nil {
		return fail(err)
	}
	if err := gen.AuthenticateNativeMaterial(ctx, r, fresh); err != nil {
		return fail(err)
	}
	material, err := nativeEngineMaterial(fresh)
	if err != nil {
		return fail(err)
	}
	if err := physical.Seal(ctx, material); err != nil {
		return fail(err)
	}
	return t, nil
}

func OpenNative(ctx context.Context, r *trustload.Runtime, home, id string) (*Transaction, error) {
	physical, err := engine.Open(ctx, r, engine.NativeGeneratorKind, home, id)
	if err != nil {
		return nil, err
	}
	t := &Transaction{physical: physical, runtime: r}
	if err := t.authenticate(ctx); err != nil {
		t.Release()
		return nil, err
	}
	if err := physical.Admit(ctx); err != nil {
		t.Release()
		return nil, err
	}
	return t, nil
}

func (t *Transaction) authenticate(ctx context.Context) error {
	if t == nil || t.physical == nil || t.runtime == nil {
		return ErrAuthentication
	}
	material := t.physical.Material()
	var intent gen.NativeMaterial
	if err := canonicaljson.DecodeStrict(material.Intent, &intent); err != nil {
		return ErrAuthentication
	}
	if err := gen.AuthenticateNativeMaterial(ctx, t.runtime, intent); err != nil {
		return err
	}
	expected, err := nativeEngineMaterial(intent)
	if err != nil {
		return err
	}
	actualRaw, err := canonicaljson.Canonical(material)
	if err != nil {
		return err
	}
	expectedRaw, err := canonicaljson.Canonical(expected)
	if err != nil || !bytes.Equal(actualRaw, expectedRaw) {
		return ErrAuthentication
	}
	return nil
}

func (t *Transaction) Apply(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	return t.physical.Apply(ctx)
}

func (t *Transaction) Commit(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	return t.physical.Commit(ctx)
}

func (t *Transaction) Rollback(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	return t.physical.Rollback(ctx)
}

func nativeEngineMaterial(m gen.NativeMaterial) (engine.Material, error) {
	intent, err := canonicaljson.Canonical(m)
	if err != nil {
		return engine.Material{}, err
	}
	convert := func(in map[string]gen.NativeFile) map[string]engine.File {
		out := map[string]engine.File{}
		for name, f := range in {
			out[name] = engine.File{Data: append(engine.Bytes{}, f.Data...), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
		}
		return out
	}
	readonly := []string{}
	for name := range m.Before {
		if name == ".tplaiter/project.yaml" || name == ".tplaiter/root-template.lock.json" || name == ".tplaiter/template.lock.json" || name == ".tplaiter/resources.lock.json" || strings.HasPrefix(name, ".tplaiter/generators/") {
			readonly = append(readonly, name)
		}
	}
	sort.Strings(readonly)
	return engine.Material{Root: m.Root, Home: m.Home, ProjectID: m.ProjectID, Binding: m.Binding, Before: convert(m.Before), After: convert(m.After), Fingerprint: m.Fingerprint, ReadOnlyPaths: readonly, Intent: intent}, nil
}
