package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/execx"
)

// ErrPreparingAmbiguous preserves an unrecorded or replaced staging inode. An
// identical hash or slot label cannot authorize its adoption or removal.
var ErrPreparingAmbiguous = errors.New("project transaction: ambiguous preparing staging; preserved")

// continuePreparing runs only under the admitted native writer's actual leases.
// A cold caller must first reconstruct and authenticate signed Update material.
// The durable prefix binds every reusable slot inode; missing steps are staged
// exclusively. A crash between slot creation and prefix publication deliberately
// leaves an unresolved orphan, never an implicit recovery ownership grant.
func (t *Transaction) continuePreparing(ctx context.Context) error {
	if !pairedKind(t.plan.Kind) || t.state.Phase != "preparing" {
		return ErrAuthentication
	}
	if err := t.checkPreparing(ctx); err != nil {
		return err
	}
	expected := t.expectedSteps()
	for i := len(t.state.Steps); i < len(expected); i++ {
		if err := t.checkPreparing(ctx); err != nil {
			return err
		}
		s := expected[i]
		s.Slot = fmt.Sprintf("%06d", i)
		before, after, _ := t.stepFiles(s)
		if s.Delete {
			s.AfterIdentity = Identity{before.Device, before.Inode}
		} else {
			id, err := t.stagePreparing(ctx, s, after)
			if err != nil {
				return err
			}
			s.AfterIdentity = id
		}
		next := t.state
		next.Steps = append(append([]step{}, t.state.Steps...), s)
		if err := t.writeSigned("state.json", next, false); err != nil {
			return err
		}
		t.state = next
	}
	if err := t.checkPreparing(ctx); err != nil {
		return err
	}
	next := t.state
	next.Phase = "prepared"
	if err := t.writeSigned("state.json", next, false); err != nil {
		return err
	}
	t.state = next
	return nil
}

func (t *Transaction) checkPreparing(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if err := t.validateSteps(); err != nil {
		return err
	}
	var actual progress
	if err := t.readProjectSigned(ctx, "state.json", &actual); err != nil {
		return err
	}
	want, err := canonicaljson.Canonical(t.state)
	if err != nil {
		return err
	}
	got, err := canonicaljson.Canonical(actual)
	if err != nil || !bytes.Equal(want, got) {
		return ErrAuthentication
	}
	for _, storage := range []struct {
		path string
		id   Identity
	}{{t.images, t.state.ImageIdentity}, {t.dir, t.state.ReceiptIdentity}} {
		info, err := confinedLstat(storage.path)
		if storage.id.Inode == 0 || err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || fileID(info) != storage.id {
			return ErrPreparingAmbiguous
		}
	}
	// Before any staging write, prove the complete current project and registry
	// preimage. No unrecorded afterimage has yet reached the public namespace.
	for name, before := range t.plan.Material.Before {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkPath(filepath.Join(t.plan.Material.Root, name), before, Identity{before.Device, before.Inode}); err != nil {
			return err
		}
	}
	for name := range t.plan.Material.After {
		if _, exists := t.plan.Material.Before[name]; !exists {
			if _, err := confinedLstat(filepath.Join(t.plan.Material.Root, name)); !os.IsNotExist(err) {
				return ErrConflict
			}
		}
	}
	if err := t.checkRegistryObservation(); err != nil {
		return err
	}
	recorded := map[string]bool{}
	for _, s := range t.state.Steps {
		if s.Intent || s.Done || s.Undone {
			return ErrAuthentication
		}
		if err := t.checkNamespace(s); err != nil {
			return err
		}
		before, after, _ := t.stepFiles(s)
		if s.Delete {
			if s.AfterIdentity != (Identity{before.Device, before.Inode}) {
				return ErrAuthentication
			}
			continue
		}
		if err := checkPath(t.slotPath(s), after, s.AfterIdentity); err != nil {
			return errors.Join(ErrPreparingAmbiguous, err)
		}
		if after.Directory {
			entries, err := confinedReadDir(t.slotPath(s))
			if err != nil || len(entries) != 0 {
				return ErrPreparingAmbiguous
			}
		}
		recorded[t.slotPath(s)] = true
	}
	for _, dir := range []string{t.images, t.dir} {
		entries, err := confinedReadDir(dir)
		if err != nil || len(entries) > 4096 {
			return ErrPreparingAmbiguous
		}
		for _, entry := range entries {
			if dir == t.dir && (entry.Name() == "plan.json" || entry.Name() == "state.json") {
				continue
			}
			if !recorded[filepath.Join(dir, entry.Name())] {
				return ErrPreparingAmbiguous
			}
		}
	}
	return ctx.Err()
}

func (t *Transaction) stagePreparing(ctx context.Context, s step, after File) (Identity, error) {
	name := t.slotPath(s)
	root, base, err := confinedParent(name)
	if err != nil {
		return Identity{}, err
	}
	defer root.Close()
	_, expectedParent := t.slotDirectory(s)
	parentInfo, err := root.Stat(".")
	if err != nil || fileID(parentInfo) != expectedParent || checkStorageParent(root, name) != nil {
		return Identity{}, ErrPreparingAmbiguous
	}
	if _, err := root.Lstat(base); !os.IsNotExist(err) {
		return Identity{}, ErrPreparingAmbiguous
	}
	if after.Directory {
		if err := ctx.Err(); err != nil {
			return Identity{}, err
		}
		if after.Mode == 0o755 {
			parent, err := root.Open(".")
			if err != nil {
				return Identity{}, err
			}
			err = execx.MkdirAtParent(ctx, parent, parentInfo, base)
			closeErr := parent.Close()
			if err := errors.Join(err, closeErr); err != nil {
				return Identity{}, err
			}
		} else if err := root.Mkdir(base, os.FileMode(after.Mode)); err != nil {
			return Identity{}, err
		}
		info, err := root.Lstat(base)
		if err != nil {
			return Identity{}, err
		}
		id := fileID(info)
		if err := checkPath(name, after, id); err != nil {
			return Identity{}, err
		}
		if err := checkStorageParent(root, name); err != nil {
			return Identity{}, err
		}
		return id, syncStorageRoot(root)
	}
	f, err := root.OpenFile(base, exclusiveFlags(), os.FileMode(after.Mode))
	if err != nil {
		return Identity{}, err
	}
	defer f.Close()
	if _, err := f.Write(after.Data); err != nil {
		return Identity{}, err
	}
	if err := f.Chmod(os.FileMode(after.Mode)); err != nil {
		return Identity{}, err
	}
	if err := f.Sync(); err != nil {
		return Identity{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return Identity{}, err
	}
	id := fileID(info)
	if err := checkPath(name, after, id); err != nil {
		return Identity{}, err
	}
	if err := checkStorageParent(root, name); err != nil {
		return Identity{}, err
	}
	return id, syncStorageRoot(root)
}
