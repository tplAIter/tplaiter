package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"gopkg.in/yaml.v3"
)

// AdoptionTransaction scopes the v2 state machine to a concrete authenticated
// transaction. Its guarded persistence/publication primitives cover preparing,
// applying, commit and every rollback advancement. V1 uses the unchanged engine.
// Embedding is internal to this package: callers cannot construct this wrapper.
type AdoptionTransaction struct {
	*Transaction
	ctx context.Context
}

func ScopeAdoption(ctx context.Context, t *Transaction) (*AdoptionTransaction, error) {
	if t == nil || t.plan.Kind != NativeUpdateKind || ctx == nil {
		return nil, ErrAuthentication
	}
	a := &AdoptionTransaction{Transaction: t, ctx: ctx}
	if err := a.guard(ctx); err != nil {
		return nil, err
	}
	return a, nil
}
func (t *AdoptionTransaction) guard(ctx context.Context) error {
	m := t.plan.Material
	var in struct {
		Version    int                        `json:"version"`
		Protection *adoptionpolicy.Protection `json:"protection"`
	}
	if json.Unmarshal(m.Intent, &in) != nil || in.Version != 2 || in.Protection == nil {
		return ErrAuthentication
	}
	var marker stateledger.ProjectV2
	if yaml.Unmarshal(m.Before[".tplaiter/project.yaml"].Data, &marker) != nil {
		return ErrAuthentication
	}
	p, err := adoptionpolicy.Parse(marker.Ownership)
	if err != nil || p == nil {
		return ErrAuthentication
	}
	if err = t.authenticate(ctx); err != nil {
		return err
	}
	proof, err := ReadAdoptionOrigin(ctx, t.runtime, m.Home, p)
	f := in.Protection
	if err != nil || f.DecisionSHA256 != p.DecisionSHA256 || f.ReceiptID != proof.ReceiptID() || f.PlanSHA256 != proof.PlanDigest() || f.ReceiptSHA256 != proof.ReceiptDigest() {
		return ErrAuthentication
	}
	names := map[string]bool{".": true}
	for _, rel := range p.Paths() {
		for {
			names[rel] = true
			if rel == "." {
				break
			}
			rel = path.Dir(rel)
		}
	}
	ordered := make([]string, 0, len(names))
	for rel := range names {
		ordered = append(ordered, rel)
	}
	sort.Strings(ordered)
	if len(f.Paths) != len(ordered) {
		return ErrAuthentication
	}
	for i, protected := range f.Paths {
		if protected.Path != ordered[i] {
			return ErrAuthentication
		}
		rel, v := protected.Path, protected.Observation
		before, exists := m.Before[rel]
		after, remains := m.After[rel]
		if exists != v.Exists || exists != remains || exists && (!sameFile(before, after) || before.Device != after.Device || before.Inode != after.Inode || before.Directory != v.Directory || before.Mode != v.Mode&0o777 || before.Device != v.Device || before.Inode != v.Inode || evidencecas.Digest(before.Data) != v.SHA256) {
			return ErrAuthentication
		}
		info, e := confinedLstat(filepath.Join(m.Root, rel))
		if !exists {
			if !os.IsNotExist(e) {
				return ErrConflict
			}
			continue
		}
		if e != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != v.Directory || !v.Directory && (!info.Mode().IsRegular() || !singleLink(info)) || fileID(info) != (Identity{v.Device, v.Inode}) || uint32(info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)) != v.Mode {
			return ErrConflict
		}
		if e = checkPath(filepath.Join(m.Root, rel), before, Identity{v.Device, v.Inode}); e != nil {
			return e
		}
		final, e := confinedLstat(filepath.Join(m.Root, rel))
		if e != nil || !os.SameFile(info, final) || info.Mode() != final.Mode() {
			return ErrConflict
		}
	}
	for _, image := range []map[string]File{m.Before, m.After} {
		refmat := m
		refmat.Before = image
		refs, e := inspectionReferences(refmat)
		if e != nil {
			return e
		}
		for _, ref := range refs {
			if _, e = t.runtime.Read(ctx, ref); e != nil {
				return e
			}
		}
	}
	if t.durable {
		var actual immutable
		if err = t.readProjectSigned(ctx, "plan.json", &actual); err != nil {
			return err
		}
		want, e := canonicaljson.Canonical(t.plan)
		if e != nil {
			return e
		}
		raw, e := canonicaljson.Canonical(actual)
		if e != nil || !bytes.Equal(want, raw) {
			return ErrAuthentication
		}
	}
	return nil
}
func (t *AdoptionTransaction) writeSigned(ctx context.Context, name string, v any, exclusive bool) error {
	if err := t.guard(ctx); err != nil {
		return err
	}
	return t.Transaction.writeSigned(name, v, exclusive)
}
func (t *AdoptionTransaction) save(ctx context.Context) error {
	return t.writeSigned(ctx, "state.json", t.state, false)
}
func (t *AdoptionTransaction) publish(ctx context.Context, s step, exchange bool) error {
	if err := t.guard(ctx); err != nil {
		return err
	}
	return t.Transaction.publish(s, exchange)
}
func (t *AdoptionTransaction) quarantine(ctx context.Context, s step) error {
	if err := t.guard(ctx); err != nil {
		return err
	}
	return t.Transaction.quarantine(s)
}
func (t *AdoptionTransaction) stagePreparing(ctx context.Context, s step, after File) (Identity, error) {
	if err := t.guard(ctx); err != nil {
		return Identity{}, err
	}
	return t.Transaction.stagePreparing(ctx, s, after)
}
func (t *AdoptionTransaction) Admit(ctx context.Context) error {
	if err := t.guard(ctx); err != nil {
		return err
	}
	return t.Transaction.Admit(ctx)
}

func (t *AdoptionTransaction) Seal(ctx context.Context, m Material) error {
	if t.lease == nil || t.admitted || m.Root != t.plan.Material.Root || m.Home != t.plan.Material.Home || m.ProjectID != t.plan.Material.ProjectID {
		return ErrAuthentication
	}
	if err := t.rejectActiveJournals(ctx); err != nil {
		return err
	}
	if err := t.recheckLockedMaterial(m); err != nil {
		return err
	}
	for name, before := range m.Before {
		after, ok := m.After[name]
		if (!ok && (!pairedKind(t.plan.Kind) || before.Directory)) || before.Directory && !sameFile(before, after) {
			return ErrUnsupported
		}
	}
	if err := t.checkRegistryMaterial(m); err != nil {
		return err
	}
	t.plan.Material = m
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	err := t.prepare(ctx, m)
	if err == nil {
		t.admitted = true
	}
	return err
}

func (t *AdoptionTransaction) prepare(ctx context.Context, m Material) error {
	fail := func(err error) error { return err }
	var err error
	kind := t.plan.Kind
	if kind != NativeUpdateKind {
		return ErrAuthentication
	}
	if err := t.guard(ctx); err != nil {
		return err
	}
	if err := privateDirectory(t.dir); err != nil {
		return fail(err)
	}
	if err := t.writeSigned(ctx, "plan.json", t.plan, true); err != nil {
		return fail(err)
	}
	if err := t.guard(ctx); err != nil {
		return err
	}
	if err := privateDirectory(t.images); err != nil {
		return fail(err)
	}
	imageInfo, err := confinedLstat(t.images)
	if err != nil {
		return fail(err)
	}
	receiptInfo, err := confinedLstat(t.dir)
	if err != nil {
		return err
	}
	t.state = progress{ReceiptIdentity: fileID(receiptInfo), ImageIdentity: fileID(imageInfo), APIVersion: APIVersion, Kind: kind, ID: t.plan.ID, Fingerprint: m.Fingerprint, Phase: "preparing", Steps: []step{}}
	if err := t.save(ctx); err != nil {
		return fail(err)
	}
	t.durable = true
	return t.continuePreparing(ctx)
}

func (t *AdoptionTransaction) Apply(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lease == nil || !t.admitted {
		return ErrActive
	}
	if t.pendingCommit != nil {
		return ErrCommitUncertain
	}
	if t.state.Phase == "committed" {
		return nil
	}
	if pairedKind(t.plan.Kind) && t.state.Phase == "preparing" {
		if err := t.continuePreparing(ctx); err != nil {
			return err
		}
	}
	if t.state.Phase != "prepared" && t.state.Phase != "applying" {
		return ErrAuthentication
	}
	if err := t.authenticate(ctx); err != nil {
		if t.state.Phase == "applying" {
			return t.rollbackAfter(ctx, err)
		}
		return err
	}
	t.state.Phase = "applying"
	if err := t.save(ctx); err != nil {
		return err
	}
	for i := range t.state.Steps {
		if err := ctx.Err(); err != nil {
			return t.rollbackAfter(ctx, err)
		}
		if err := t.authenticate(ctx); err != nil {
			return t.rollbackAfter(ctx, err)
		}
		if err := t.checkObservations(ctx); err != nil {
			return t.rollbackAfter(ctx, err)
		}
		if err := t.applyStep(ctx, i); err != nil {
			return t.rollbackAfter(ctx, err)
		}
	}
	return nil
}

func (t *AdoptionTransaction) Commit(ctx context.Context) error {
	// A published-but-not-confirmed receipt cannot be treated as applying or
	// rolled back. Retry/cold open confirms the exact terminal receipt first.
	t.mu.Lock()
	if t.pendingCommit != nil || t.state.Phase == "committed" {
		err := t.confirmCommit(ctx)
		t.mu.Unlock()
		return err
	}
	t.mu.Unlock()
	if err := t.Apply(ctx); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pendingCommit != nil || t.state.Phase == "committed" {
		return t.confirmCommit(ctx)
	}
	if err := t.authenticate(ctx); err != nil {
		return t.rollbackAfter(ctx, err)
	}
	if pairedKind(t.plan.Kind) {
		if err := t.checkObservations(ctx); err != nil {
			return t.rollbackAfter(ctx, err)
		}
	}
	if err := t.readonlyBindings(); err != nil {
		return t.rollbackAfter(ctx, err)
	}
	for _, step := range t.state.Steps {
		if err := t.checkStepFinal(step); err != nil {
			return t.rollbackAfter(ctx, err)
		}
	}
	terminal := t.state
	terminal.Steps = append([]step{}, t.state.Steps...)
	terminal.Phase = "committed"
	// The live phase changes only after a successful durable publication.
	if err := t.writeSigned(ctx, "state.json", terminal, false); err != nil {
		var published *publishedWriteError
		if errors.As(err, &published) {
			t.pendingCommit = &terminal
		}
		return err
	}
	t.state = terminal
	return nil
}

func (t *AdoptionTransaction) Rollback(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lease == nil || !t.admitted {
		return ErrActive
	}
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if err := t.readonlyBindings(); err != nil {
		return err
	}
	return t.rollback(ctx)
}

func (t *AdoptionTransaction) rollbackAfter(ctx context.Context, cause error) error {
	return errors.Join(cause, t.rollback(context.WithoutCancel(ctx)))
}

func (t *AdoptionTransaction) rollback(ctx context.Context) error {
	if t.pendingCommit != nil {
		return ErrCommitUncertain
	}
	if t.state.Phase == "committed" {
		return ErrAuthentication
	}
	if t.state.Phase == "rolled-back" {
		return t.confirmRollback(ctx)
	}
	t.state.Phase = "rolling-back"
	if err := t.save(ctx); err != nil {
		return err
	}
	var failures []error
	for i := len(t.state.Steps) - 1; i >= 0; i-- {
		if err := t.undoStep(ctx, i); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", t.state.Steps[i].Path, err))
		}
	}
	terminal := t.state
	terminal.Steps = append([]step{}, t.state.Steps...)
	if len(failures) == 0 {
		terminal.Phase = "rolled-back"
	} else {
		terminal.Phase = "rollback-conflicts"
	}
	// A terminal rollback becomes live only after its durable receipt succeeds.
	// On failure retry repeats owned-state checks and persists the receipt again.
	persistErr := t.writeSigned(ctx, "state.json", terminal, false)
	if persistErr == nil {
		t.state = terminal
	}
	return errors.Join(errors.Join(failures...), persistErr)
}

func (t *AdoptionTransaction) applyStep(ctx context.Context, i int) error {
	s := &t.state.Steps[i]
	if s.Delete {
		return t.applyDelete(ctx, i)
	}
	before, after, exists := t.stepFiles(*s)
	if s.Done {
		return t.checkTarget(*s, after, s.AfterIdentity)
	}
	// Reconcile a crash after exchange but before the completion record.
	if s.Intent && t.checkTarget(*s, after, s.AfterIdentity) == nil {
		if exists && checkPath(t.slotPath(*s), before, Identity{before.Device, before.Inode}) != nil {
			return ErrConflict
		}
		s.Done = true
		return t.save(ctx)
	}
	if exists {
		if err := t.checkTarget(*s, before, Identity{before.Device, before.Inode}); err != nil {
			return err
		}
	} else {
		if _, err := confinedLstat(filepath.Join(t.plan.Material.Root, s.Path)); !os.IsNotExist(err) {
			return ErrConflict
		}
	}
	if err := checkPath(t.slotPath(*s), after, s.AfterIdentity); err != nil {
		return err
	}
	s.Intent = true
	if err := t.save(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.publish(ctx, *s, exists); err != nil {
		return err
	}
	if exists && checkPath(t.slotPath(*s), before, Identity{before.Device, before.Inode}) != nil {
		// A foreign replacement raced the exchange. Put that exact inode back only
		// while the destination still contains our prepared inode.
		if t.checkTarget(*s, after, s.AfterIdentity) == nil {
			_ = t.publish(ctx, *s, true)
		}
		return ErrConflict
	}
	if err := t.checkTarget(*s, after, s.AfterIdentity); err != nil {
		return err
	}
	s.Done = true
	return t.save(ctx)
}

func (t *AdoptionTransaction) undoStep(ctx context.Context, i int) error {
	s := &t.state.Steps[i]
	if s.Undone {
		return nil
	}
	if s.Delete {
		return t.undoDelete(ctx, i)
	}
	before, after, existed := t.stepFiles(*s)
	target := t.targetPath(*s)
	slot := t.slotPath(*s)
	// A step not published (or already reverted before a crash) needs no write.
	if existed && t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil && checkPath(slot, after, s.AfterIdentity) == nil {
		s.Undone = true
		return t.save(ctx)
	}
	if !existed {
		if _, err := confinedLstat(target); os.IsNotExist(err) && checkPath(slot, after, s.AfterIdentity) == nil {
			s.Undone = true
			return t.save(ctx)
		}
	}
	if err := t.checkTarget(*s, after, s.AfterIdentity); err != nil {
		return err
	}
	if after.Directory {
		entries, err := confinedReadDir(target)
		if err != nil || len(entries) != 0 {
			return ErrConflict
		}
	}
	if existed {
		if err := checkPath(slot, before, Identity{before.Device, before.Inode}); err != nil {
			return err
		}
		if err := t.publish(ctx, *s, true); err != nil {
			return err
		}
		if checkPath(slot, after, s.AfterIdentity) != nil { // Undo encountered a raced foreign inode; restore it.
			if t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil {
				_ = t.publish(ctx, *s, true)
			}
			return ErrConflict
		}
	} else {
		if err := t.quarantine(ctx, *s); err != nil {
			return err
		}
		if checkPath(slot, after, s.AfterIdentity) != nil {
			_ = t.publish(ctx, *s, false)
			return ErrConflict
		}
	}
	s.Undone = true
	return t.save(ctx)
}

func (t *AdoptionTransaction) continuePreparing(ctx context.Context) error {
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
		if err := t.writeSigned(ctx, "state.json", next, false); err != nil {
			return err
		}
		t.state = next
	}
	if err := t.checkPreparing(ctx); err != nil {
		return err
	}
	next := t.state
	next.Phase = "prepared"
	if err := t.writeSigned(ctx, "state.json", next, false); err != nil {
		return err
	}
	t.state = next
	return nil
}

func (t *AdoptionTransaction) applyDelete(ctx context.Context, i int) error {
	s := &t.state.Steps[i]
	before, _, _ := t.stepFiles(*s)
	if s.Done {
		return t.checkDeleted(*s)
	}
	if s.Intent && t.checkDeleted(*s) == nil {
		s.Done = true
		return t.save(ctx)
	}
	if err := t.checkTarget(*s, before, Identity{before.Device, before.Inode}); err != nil {
		return err
	}
	if _, err := confinedLstat(t.slotPath(*s)); !os.IsNotExist(err) {
		return ErrConflict
	}
	s.Intent = true
	if err := t.save(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.quarantine(ctx, *s); err != nil {
		return err
	}
	if err := checkPath(t.slotPath(*s), before, Identity{before.Device, before.Inode}); err != nil {
		// A raced foreign inode was moved, not deleted. Restore it exclusively if
		// the destination is still absent; otherwise retain it and report ambiguity.
		restore := t.publish(ctx, *s, false)
		return errors.Join(ErrConflict, restore)
	}
	if err := t.checkDeleted(*s); err != nil {
		return err
	}
	s.Done = true
	return t.save(ctx)
}

func (t *AdoptionTransaction) undoDelete(ctx context.Context, i int) error {
	s := &t.state.Steps[i]
	before, _, _ := t.stepFiles(*s)
	if t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil {
		if _, err := confinedLstat(t.slotPath(*s)); !os.IsNotExist(err) {
			return ErrConflict
		}
		s.Undone = true
		return t.save(ctx)
	}
	if err := t.checkDeleted(*s); err != nil {
		return err
	}
	if err := t.publish(ctx, *s, false); err != nil {
		return err
	}
	if err := t.checkTarget(*s, before, Identity{before.Device, before.Inode}); err != nil {
		return fmt.Errorf("%w: restored deletion: %w", ErrConflict, err)
	}
	s.Undone = true
	return t.save(ctx)
}
