package newtransaction

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/newtransaction/inspect"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// ErrOwnershipUncertain retains the journal and all ambiguous content. Neither
// recovery nor abort may turn an observed tree into publication authority.
var ErrOwnershipUncertain = inspect.ErrOwnershipUncertain

// BeginSealedWithFault binds an initially empty target to caller-derived output
// bytes before any staging writes. Files have mode 0644, parent directories
// 0755, and the transaction-owned state directory 0700. The inventory is never
// derived from the mutable workspace. Production callers pass a nil fault.
func BeginSealedWithFault(home, target string, files map[string][]byte, fault FaultInjector) (*Transaction, error) {
	if managedImages(files) {
		return nil, ErrManagedAdmission
	}
	tree, err := outputTree(files)
	if err != nil {
		return nil, err
	}
	return begin(home, target, fault, digest(tree))
}

func outputTree(files map[string][]byte) ([]byte, error) {
	entries := map[string]string{".tplaiter": "dir\x00700\x00"}
	for name, raw := range files {
		if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\n\x00") || name == filepath.ToSlash(pendingMarkerRel) {
			return nil, ErrUnsafe
		}
		if _, exists := entries[name]; exists {
			return nil, ErrUnsafe
		}
		entries[name] = "file\x00644\x00" + digest(raw)
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if entry, exists := entries[parent]; exists && !strings.HasPrefix(entry, "dir\x00") {
				return nil, ErrUnsafe
			}
			if parent != ".tplaiter" {
				entries[parent] = "dir\x00755\x00"
			}
		}
	}
	lines := make([]string, 0, len(entries))
	for name, entry := range entries {
		lines = append(lines, name+"\x00"+entry)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n")), nil
}

// SealOutputs acknowledges a completely written afterimage, only after checking
// it against the inventory supplied to BeginSealedWithFault. Recovery refuses
// publication until this acknowledgement is durable.
func (t *Transaction) SealOutputs() error {
	if err := t.checkManaged(context.Background(), false, nil); err != nil {
		return err
	}
	if t == nil || t.sealedTree == "" || t.j.Phase != Prepared {
		return ErrUnsafe
	}
	if err := t.verifySealedTree(t.j.Staging); err != nil {
		return err
	}
	t.sealedReady = true
	return t.save()
}

func (t *Transaction) verifySealedTree(root string) error {
	raw, err := snapshotTree(root)
	if err != nil || digest(raw) != t.sealedTree {
		return fmt.Errorf("%w: sealed afterimage differs", ErrOwnershipUncertain)
	}
	return nil
}

// Before staging, only the exact beforeimage is owned. After staging but before
// SealOutputs, only that image plus the transaction's empty state directory is
// safely abortable. Partial writes are deliberately retained, not guessed away.
func (t *Transaction) verifySealedAbort() error {
	if _, err := os.Lstat(filepath.Join(t.j.Staging, pendingMarkerRel)); err == nil {
		if err := t.verifyPendingAt(t.j.Staging); err != nil {
			return errors.Join(ErrOwnershipUncertain, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(ErrOwnershipUncertain, err)
	}
	if t.sealedReady {
		return t.verifySealedTree(t.j.Staging)
	}
	raw, err := snapshotTree(t.j.Staging)
	if err != nil {
		return err
	}
	if digest(raw) == t.j.TargetBeforeTreeSHA || (t.j.TargetBeforeTreeSHA == digest(nil) && string(raw) == ".tplaiter\x00dir\x00700\x00") {
		return nil
	}
	return ErrOwnershipUncertain
}

// ErrManagedAdmission retains all transaction evidence when generic recovery
// lacks the signed source and actual formatter publication carrier.
var ErrManagedAdmission = errors.New("new transaction: managed publication requires typed source-bound recovery")

func managedImages(files map[string][]byte) bool {
	for name, raw := range files {
		if name == ".tplaiter/managed-blocks.json" {
			baseline, err := managedblocks.ParseBaseline(raw)
			if err != nil || len(baseline.Files) != 0 {
				return true
			}
		}
		if name == ".tplaiter/managed-lineage.json" || (strings.HasSuffix(name, ".go") && bytes.Contains(raw, []byte("tplater:managed-"))) {
			return true
		}
	}
	return false
}

// BeginManagedSealed accepts only the opaque source-owner publication. It never
// takes caller afterimages, reported receipts, or a supplied sealing key.
func BeginManagedSealed(ctx context.Context, r *trustload.Runtime, publication *formatproof.NewPublication) (*Transaction, error) {
	if ctx == nil || r == nil || publication == nil {
		return nil, ErrManagedAdmission
	}
	if err := publication.RevalidatePublication(ctx, r); err != nil {
		return nil, err
	}
	files, err := publication.ImagesFor(ctx, r)
	if err != nil {
		return nil, err
	}
	home, _, _, err := publication.RegistryFor(r)
	if err != nil {
		return nil, err
	}
	tree, err := outputTree(files)
	if err != nil {
		return nil, err
	}
	tx, err := begin(home, r.ProjectContext().RootPath, nil, digest(tree))
	if err != nil {
		return nil, err
	}
	reference := publication.Reference()
	tx.managedReference, tx.managedRuntime = &reference, r
	if err := tx.save(); err != nil {
		tx.Release()
		return nil, err
	}
	return tx, nil
}

// checkManaged is also used by generic entrypoints. A stripped recovery branch
// cannot convert managed content into ordinary sealed publication authority.
func (t *Transaction) checkManaged(ctx context.Context, fresh bool, plan *RegistryPlan) error {
	if t == nil {
		return ErrUnsafe
	}
	if t.managedReference == nil {
		for _, root := range []string{t.j.Staging, t.j.Target} {
			if err := refuseManagedTree(root); err != nil {
				return err
			}
		}
		return nil
	}
	if t.managedRuntime == nil || t.managedRuntime.ProjectContext().RootPath != t.j.Target {
		return ErrManagedAdmission
	}
	publication, err := formatproof.OpenNewPublication(ctx, t.managedRuntime, *t.managedReference)
	if err != nil {
		return err
	}
	images, err := publication.ImagesFor(ctx, t.managedRuntime)
	if err != nil {
		return err
	}
	tree, err := outputTree(images)
	if err != nil || t.sealedTree != digest(tree) {
		return ErrManagedAdmission
	}
	home, before, after, err := publication.RegistryFor(t.managedRuntime)
	if err != nil || home != t.home {
		return ErrManagedAdmission
	}
	if plan != nil && (plan.Home != home || !bytes.Equal(plan.Before, before) || !bytes.Equal(plan.After, after)) {
		return ErrManagedAdmission
	}
	if t.j.RegistryBeforeSHA != "" && (t.j.RegistryBeforeSHA != digest(before) || t.j.RegistryAfterSHA != digest(after)) {
		return ErrManagedAdmission
	}
	if fresh {
		return publication.RevalidatePublication(ctx, t.managedRuntime)
	}
	return nil
}

func refuseManagedTree(root string) error {
	r, err := os.OpenRoot(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	return fs.WalkDir(r.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == ".tplaiter/managed-lineage.json" {
			return ErrManagedAdmission
		}
		if name == ".tplaiter/managed-blocks.json" {
			raw, err := r.ReadFile(name)
			if err != nil {
				return err
			}
			baseline, err := managedblocks.ParseBaseline(raw)
			if err != nil || len(baseline.Files) != 0 {
				return ErrManagedAdmission
			}
		}
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".go") {
			raw, err := r.ReadFile(name)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte("tplater:managed-")) {
				return ErrManagedAdmission
			}
		}
		return nil
	})
}

// ContinueManaged reconstructs the same transaction's source and formatter
// evidence. Completed effects are validated, never rerun by recovery.
func ContinueManaged(ctx context.Context, r *trustload.Runtime, home, id string) error {
	if ctx == nil || r == nil {
		return ErrManagedAdmission
	}
	return continueAdmittedTx(ctx, home, id, home, nil, r)
}

// AbortManaged preserves the ordinary geometry and ownership checks while
// admitting only the exact sealed managed source carrier.
func AbortManaged(ctx context.Context, r *trustload.Runtime, home, id string) error {
	if ctx == nil || r == nil {
		return ErrManagedAdmission
	}
	clean, err := absClean(home)
	if err != nil {
		return err
	}
	lock, err := acquireNewLock(filepath.Join(clean, "transactions", "new.lock"), id)
	if err != nil {
		return err
	}
	defer lock.Close()
	tx, err := Load(clean, id)
	if err != nil {
		return err
	}
	if tx.managedReference == nil {
		return ErrManagedAdmission
	}
	tx.managedRuntime = r
	if err := tx.checkManaged(ctx, false, nil); err != nil {
		return err
	}
	return tx.abortLocked()
}
