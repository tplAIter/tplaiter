package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func (t *Transaction) expectedSteps() []step {
	names := map[string]bool{}
	for p, a := range t.plan.Material.After {
		b, ok := t.plan.Material.Before[p]
		if !ok || !sameFile(a, b) {
			names[p] = true
		}
	}
	for p := range t.plan.Material.Before {
		if _, ok := t.plan.Material.After[p]; !ok {
			names[p] = true
		}
	}
	ordered := make([]string, 0, len(names))
	for p := range names {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	out := []step{}
	for _, p := range ordered {
		_, ok := t.plan.Material.After[p]
		out = append(out, step{Path: p, Delete: !ok})
	}
	if r := t.plan.Material.Registry; r != nil && !sameFile(r.Before, r.After) {
		out = append(out, step{Path: "projects.yaml", Registry: true})
	}
	return out
}

func (t *Transaction) stepFiles(s step) (File, File, bool) {
	if s.Registry {
		r := t.plan.Material.Registry
		return r.Before, r.After, true
	}
	b, ok := t.plan.Material.Before[s.Path]
	return b, t.plan.Material.After[s.Path], ok
}

func (t *Transaction) targetPath(s step) string {
	if s.Registry {
		return filepath.Join(t.plan.Material.Home, "projects.yaml")
	}
	return filepath.Join(t.plan.Material.Root, s.Path)
}

func (t *Transaction) slotPath(s step) string {
	if s.Registry {
		return filepath.Join(t.dir, s.Slot)
	}
	return filepath.Join(t.images, s.Slot)
}

func (t *Transaction) slotDirectory(s step) (string, Identity) {
	if s.Registry {
		return t.dir, t.state.ReceiptIdentity
	}
	return t.images, t.state.ImageIdentity
}

func (t *Transaction) sameRegistryMaterial(m Material) error {
	old := t.plan.Material.Registry
	if (old == nil) != (m.Registry == nil) {
		return ErrAuthentication
	}
	if old != nil && (!sameFile(old.Before, m.Registry.Before) || !sameFile(old.After, m.Registry.After) || old.Before.Device != m.Registry.Before.Device || old.Before.Inode != m.Registry.Before.Inode) {
		return ErrConflict
	}
	return nil
}

func (t *Transaction) checkRegistryMaterial(m Material) error {
	if m.Registry == nil {
		if pairedKind(t.plan.Kind) {
			return ErrAuthentication
		}
		return nil
	}
	if !pairedKind(t.plan.Kind) || m.Registry.Before.Directory || m.Registry.After.Directory || m.Registry.Before.Inode == 0 || m.Registry.Before.Mode > 0o777 || m.Registry.After.Mode != m.Registry.Before.Mode {
		return ErrAuthentication
	}
	return checkPath(filepath.Join(m.Home, "projects.yaml"), m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode})
}

func (t *Transaction) checkRegistryObservation() error {
	r := t.plan.Material.Registry
	if r == nil {
		return nil
	}
	for _, s := range t.state.Steps {
		if s.Registry && (s.Done || s.Intent && t.checkTarget(s, r.After, s.AfterIdentity) == nil) {
			return t.checkTarget(s, r.After, s.AfterIdentity)
		}
	}
	return checkPath(filepath.Join(t.plan.Material.Home, "projects.yaml"), r.Before, Identity{r.Before.Device, r.Before.Inode})
}

func (t *Transaction) checkDeleted(s step) error {
	if err := t.checkNamespace(s); err != nil {
		return err
	}
	if err := t.checkParents(s.Path); err != nil {
		return err
	}
	if _, err := confinedLstat(t.targetPath(s)); !os.IsNotExist(err) {
		return ErrConflict
	}
	before, _, _ := t.stepFiles(s)
	return checkPath(t.slotPath(s), before, Identity{before.Device, before.Inode})
}

func (t *Transaction) checkStepFinal(s step) error {
	if s.Delete {
		return t.checkDeleted(s)
	}
	_, a, _ := t.stepFiles(s)
	return t.checkTarget(s, a, s.AfterIdentity)
}

func (t *Transaction) applyDelete(ctx context.Context, i int) error {
	s := &t.state.Steps[i]
	before, _, _ := t.stepFiles(*s)
	if s.Done {
		return t.checkDeleted(*s)
	}
	if s.Intent && t.checkDeleted(*s) == nil {
		s.Done = true
		return t.save()
	}
	if err := t.checkTarget(*s, before, Identity{before.Device, before.Inode}); err != nil {
		return err
	}
	if _, err := confinedLstat(t.slotPath(*s)); !os.IsNotExist(err) {
		return ErrConflict
	}
	s.Intent = true
	if err := t.save(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.quarantine(*s); err != nil {
		return err
	}
	if err := checkPath(t.slotPath(*s), before, Identity{before.Device, before.Inode}); err != nil {
		// A raced foreign inode was moved, not deleted. Restore it exclusively if
		// the destination is still absent; otherwise retain it and report ambiguity.
		restore := t.publish(*s, false)
		return errors.Join(ErrConflict, restore)
	}
	if err := t.checkDeleted(*s); err != nil {
		return err
	}
	s.Done = true
	return t.save()
}

func (t *Transaction) undoDelete(i int) error {
	s := &t.state.Steps[i]
	before, _, _ := t.stepFiles(*s)
	if t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil {
		if _, err := confinedLstat(t.slotPath(*s)); !os.IsNotExist(err) {
			return ErrConflict
		}
		s.Undone = true
		return t.save()
	}
	if err := t.checkDeleted(*s); err != nil {
		return err
	}
	if err := t.publish(*s, false); err != nil {
		return err
	}
	if err := t.checkTarget(*s, before, Identity{before.Device, before.Inode}); err != nil {
		return fmt.Errorf("%w: restored deletion: %w", ErrConflict, err)
	}
	s.Undone = true
	return t.save()
}

func (t *Transaction) checkNamespace(s step) error {
	if !pairedKind(t.plan.Kind) {
		return nil
	}
	root := t.plan.Material.Root
	if s.Registry {
		root = t.plan.Material.Home
	}
	prefix := root
	for _, part := range strings.Split(filepath.ToSlash(s.Path), "/") {
		if _, err := confinedLstat(prefix); os.IsNotExist(err) {
			return nil
		}
		entries, err := confinedReadDir(prefix)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || len(entries) > 4096 {
			return ErrConflict
		}
		for _, e := range entries {
			if strings.EqualFold(e.Name(), part) && e.Name() != part {
				return ErrConflict
			}
		}
		prefix = filepath.Join(prefix, part)
	}
	return nil
}

func (t *Transaction) rejectActiveJournals() error {
	parent := filepath.Dir(t.dir)
	if _, err := confinedLstat(parent); os.IsNotExist(err) {
		return nil
	}
	entries, err := confinedReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || len(entries) > 4096 {
		return ErrAuthentication
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "tx-") {
			return ErrAuthentication
		}
		id := strings.TrimPrefix(e.Name(), "tx-")
		if len(id) != 32 {
			return ErrAuthentication
		}
		if raw, err := privateRead(filepath.Join(parent, e.Name(), "plan.json"), 128<<20); err == nil {
			var outer envelope
			var header struct {
				Kind string `json:"kind"`
			}
			if canonicaljson.DecodeStrict(raw, &outer) == nil && json.Unmarshal(outer.Payload, &header) == nil && header.Kind == NativeLinkKind {
				// Shared installation sealing proves a historical terminal
				// fence even for another named context; it grants no root authority.
				prior := &Transaction{key: t.key, dir: filepath.Join(parent, e.Name()), plan: immutable{Kind: NativeLinkKind}}
				var plan immutable
				var state firstMarkerState
				if prior.readSigned("plan.json", &plan) != nil || prior.readSigned("state.json", &state) != nil || plan.APIVersion != APIVersion || plan.Kind != NativeLinkKind || plan.ID != id || state.APIVersion != APIVersion || state.Kind != NativeLinkKind || state.ID != id || state.Fingerprint != plan.Material.Fingerprint || plan.Material.Home != t.plan.Material.Home {
					return ErrAuthentication
				}
				if state.Phase != "committed" && state.Phase != "rolled-back" {
					return ErrActive
				}
				continue
			}
		}
		var p immutable
		var state progress
		found := false
		for _, kind := range []string{NativeGeneratorKind, NativeUpdateKind, NativeWorkspaceKind} {
			prior := &Transaction{key: t.key, dir: filepath.Join(parent, e.Name()), plan: immutable{Kind: kind}}
			if prior.readSigned("plan.json", &p) == nil && prior.readSigned("state.json", &state) == nil {
				if p.APIVersion != APIVersion || state.APIVersion != APIVersion || p.ID != id || p.Kind != kind || state.ID != id || state.Kind != kind || state.Fingerprint != p.Material.Fingerprint || p.Material.Home != t.plan.Material.Home {
					return ErrAuthentication
				}
				found = true
				break
			}
		}
		if !found {
			return ErrAuthentication
		}
		if state.Phase != "committed" && state.Phase != "rolled-back" {
			return ErrActive
		}
	}
	return nil
}
