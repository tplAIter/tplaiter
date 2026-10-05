// Package link admits opaque signed link plans to the restricted first-marker engine.
package link

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

type intent struct {
	Input    linkcmd.Input  `json:"input"`
	Renderer string         `json:"renderer"`
	Stamp    string         `json:"stamp"`
	Report   linkcmd.Report `json:"report"`
}
type Transaction struct {
	physical *engine.FirstMarker
	runtime  *trustload.Runtime
	home     string
	intent   intent
}

func (t *Transaction) ID() string { return t.physical.ID() }
func (t *Transaction) Release() {
	if t != nil && t.physical != nil {
		t.physical.Release()
	}
}
func (t *Transaction) Report() linkcmd.Report {
	v := t.intent.Report
	v.Paths = append([]string{}, v.Paths...)
	v.Conflicts = append([]linkcmd.Conflict{}, v.Conflicts...)
	return v
}
func (t *Transaction) Ref() string { return t.intent.Input.Ref }
func Begin(ctx context.Context, p *linkcmd.Plan, expected, renderer string) (*Transaction, error) {
	if p == nil || p.Runtime() == nil || expected == "" || expected != p.Fingerprint() {
		return nil, engine.ErrAuthentication
	}
	m, err := material(p, renderer)
	if err != nil {
		return nil, err
	}
	f, err := engine.AcquireFirstMarker(ctx, p.Runtime(), m, p.Missing())
	if err != nil {
		return nil, err
	}
	var in intent
	if err = canonicaljson.DecodeStrict(m.Intent, &in); err != nil {
		f.Release()
		return nil, err
	}
	tx := &Transaction{physical: f, runtime: p.Runtime(), home: p.Home(), intent: in}
	fresh, err := p.Reprepare(ctx, renderer)
	if err != nil {
		tx.Release()
		return nil, err
	}
	if fresh.Fingerprint() != expected {
		tx.Release()
		return nil, engine.ErrConflict
	}
	m, err = material(fresh, renderer)
	if err == nil {
		err = f.Seal(ctx, m, fresh.Missing())
	}
	// Once a journal exists the caller retains its ID even on uncertain staging.
	if err != nil {
		return tx, err
	}
	return tx, nil
}
func Open(ctx context.Context, r *trustload.Runtime, home, id, renderer string) (*Transaction, error) {
	f, err := engine.OpenFirstMarker(ctx, r, home, id)
	if err != nil {
		return nil, err
	}
	m, err := f.Material()
	if err != nil {
		f.Release()
		return nil, err
	}
	var in intent
	if err = canonicaljson.DecodeStrict(m.Intent, &in); err != nil || in.Renderer != renderer || in.Input.Action != "link" && in.Input.Action != "adopt" {
		f.Release()
		return nil, engine.ErrAuthentication
	}
	t := &Transaction{physical: f, runtime: r, home: home, intent: in}
	if err = t.authenticate(ctx); err != nil {
		t.Release()
		return nil, err
	}
	return t, nil
}
func (t *Transaction) authenticate(ctx context.Context) error {
	m, err := t.physical.Material()
	if err != nil {
		return err
	}
	stamp, err := time.Parse(time.RFC3339Nano, t.intent.Stamp)
	if err != nil {
		return engine.ErrAuthentication
	}
	before := map[string]linkcmd.File{}
	for path, f := range m.Before {
		before[path] = linkcmd.File{Data: bytes.Clone(f.Data), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
	}
	fresh, err := linkcmd.ReconstructProjected(ctx, t.runtime, t.home, t.intent.Input, t.intent.Renderer, stamp, before)
	if err != nil {
		return err
	}
	if len(fresh) != len(m.After) {
		return engine.ErrAuthentication
	}
	for name, raw := range fresh {
		after, ok := m.After[name]
		if !ok || !bytes.Equal(raw, after.Data) || after.Directory || after.Mode != managedMode(name) {
			return engine.ErrAuthentication
		}
	}
	return nil
}
func (t *Transaction) Commit(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	return t.physical.Commit(ctx)
}
func (t *Transaction) Abort(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	return t.physical.Abort(ctx)
}
func material(p *linkcmd.Plan, renderer string) (engine.Material, error) {
	r := p.Runtime()
	if r == nil || r.TrustRuntime() == nil {
		return engine.Material{}, engine.ErrAuthentication
	}
	reg, after := p.Registry()
	mode := reg.Mode
	if reg.Inode == 0 {
		mode = 0o600
	}
	m := engine.Material{Root: r.ProjectContext().RootPath, Home: p.Home(), ProjectID: r.ProjectContext().ProjectID, Binding: r.TrustRuntime().Binding(), Fingerprint: p.Fingerprint(), Before: map[string]engine.File{}, After: map[string]engine.File{}, ReadOnlyPaths: []string{}, Registry: &engine.RegistryPair{Before: convert(reg), After: engine.File{Data: after, Mode: mode}}}
	for name, f := range p.Before() {
		m.Before[name] = convert(f)
	}
	for name, raw := range p.Images() {
		m.After[name] = engine.File{Data: raw, Mode: managedMode(name)}
	}
	in := intent{p.Input(), renderer, p.Stamp().Format(time.RFC3339Nano), p.Report()}
	raw, err := canonicaljson.Canonical(in)
	if err != nil {
		return engine.Material{}, err
	}
	m.Intent = raw
	if _, ok := m.Before["."]; !ok || reflect.DeepEqual(m.After, map[string]engine.File{}) {
		return engine.Material{}, errors.New("link: empty material")
	}
	return m, nil
}
func convert(f linkcmd.File) engine.File {
	return engine.File{Data: engine.Bytes(f.Data), Mode: f.Mode, Directory: f.Directory, Device: f.Device, Inode: f.Inode}
}

func managedMode(name string) uint32 {
	if name == ".tplaiter/update.lock" {
		return 0o600
	}
	return 0o644
}
