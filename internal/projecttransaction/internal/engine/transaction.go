// Package engine owns durable in-place project mutations. Concrete operation
// adapters provide authenticated admission through a restricted internal boundary. Journal data
// never supplies a signing key, trusted bit, runtime or source authority.
package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const (
	APIVersion          = "tplaiter.dev/project-transaction/v1"
	NativeGeneratorKind = "NativeGeneratorTransaction"
	NativeUpdateKind    = "NativeUpdateTransaction"
)

var (
	ErrConflict          = errors.New("project transaction: foreign ownership; preserved")
	ErrAuthentication    = errors.New("project transaction: authentication refused")
	ErrCommitUncertain   = errors.New("project transaction: terminal receipt publication uncertain")
	ErrUnsupported       = errors.New("project transaction: operation not supported")
	ErrActive            = errors.New("project transaction: lease held")
	ErrPreparingContinue = errors.New("project transaction: preparing Continue unsupported")
)

type Identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type immutable struct {
	APIVersion   string   `json:"apiVersion"`
	Kind         string   `json:"kind"`
	ID           string   `json:"id"`
	HomeIdentity Identity `json:"homeIdentity"`
	RootIdentity Identity `json:"rootIdentity"`
	Material     Material `json:"material"`
}
type step struct {
	Delete        bool     `json:"delete,omitempty"`
	Registry      bool     `json:"registry,omitempty"`
	Path          string   `json:"path"`
	Slot          string   `json:"slot"`
	AfterIdentity Identity `json:"afterIdentity"`
	Intent        bool     `json:"intent"`
	Done          bool     `json:"done"`
	Undone        bool     `json:"undone"`
}
type progress struct {
	ReceiptIdentity Identity `json:"receiptIdentity,omitempty"`
	APIVersion      string   `json:"apiVersion"`
	Kind            string   `json:"kind"`
	ID              string   `json:"id"`
	Fingerprint     string   `json:"fingerprint"`
	Phase           string   `json:"phase"`
	ImageIdentity   Identity `json:"imageIdentity"`
	Steps           []step   `json:"steps"`
}
type envelope struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}
type Transaction struct {
	mu                sync.Mutex
	runtime           *trustload.Runtime
	plan              immutable
	state             progress
	dir, images       string
	lease             *os.File
	admitted          bool
	durable           bool
	pendingCommit     *progress
	commitFault       commitWriteFault
	rollbackFault     commitWriteFault
	rollbackSyncFault receiptSyncFault
	writerLocks       []*os.File
	key               []byte // runtime-owned secret; never exposed, logged or accepted as input
}

func (t *Transaction) ID() string {
	if !t.durable {
		return ""
	}
	return t.plan.ID
}

func (t *Transaction) Release() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lease != nil {
		t.lease.Close()
		t.lease = nil
	}
	for _, f := range t.writerLocks {
		_ = f.Close()
	}
	t.writerLocks = nil
	for i := range t.key {
		t.key[i] = 0
	}
	t.key = nil
}

// BeginNative persists authenticated immutable before/after images and all
// prepared afterimage inodes before changing any project artifact. Root stays
// present throughout. No caller-supplied material or signature is admitted.
func Acquire(ctx context.Context, runtime *trustload.Runtime, kind string, m Material) (*Transaction, error) {
	if kind != NativeGeneratorKind && kind != NativeUpdateKind {
		return nil, ErrAuthentication
	}
	if runtime == nil || runtime.TrustRuntime() == nil {
		return nil, ErrAuthentication
	}
	if m.Home == "" || !filepath.IsAbs(m.Home) || filepath.Clean(m.Home) != m.Home || overlaps(m.Root, m.Home) {
		return nil, ErrAuthentication
	}
	key, err := runtimeKey(ctx, runtime, m.ProjectID, true)
	if err != nil {
		return nil, err
	}
	idraw := make([]byte, 16)
	if _, err := rand.Read(idraw); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idraw)
	lease, err := acquireLease(runtime, m.Root)
	if err != nil {
		return nil, err
	}
	t := &Transaction{runtime: runtime, key: key, lease: lease, plan: immutable{APIVersion: APIVersion, Kind: kind, ID: id, Material: m}, dir: journalDir(m.Home, id), images: filepath.Join(m.Root, ".tplaiter", "project-transactions", id)}
	fail := func(err error) (*Transaction, error) { t.Release(); return t, err }
	rootinfo, err := confinedLstat(m.Root)
	if err != nil {
		return fail(err)
	}
	t.plan.RootIdentity = fileID(rootinfo)
	homeInfo, err := confinedLstat(m.Home)
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 {
		return fail(ErrConflict)
	}
	t.plan.HomeIdentity = fileID(homeInfo)
	if err := t.authenticate(ctx); err != nil {
		return fail(err)
	}
	if err := t.acquireWriterLocks(); err != nil {
		return fail(err)
	}
	if err := t.authenticate(ctx); err != nil {
		return fail(err)
	}
	if err := t.rejectActiveJournals(); err != nil {
		return fail(err)
	}
	return t, nil
}

// Seal is callable only by concrete operation adapters in projecttransaction.
// It requires a fresh semantic admission AFTER Acquire, never a public caller
// material. The internal import boundary is part of this contract.
func (t *Transaction) Seal(ctx context.Context, m Material) error {
	if t.lease == nil || t.admitted || m.Root != t.plan.Material.Root || m.Home != t.plan.Material.Home || m.ProjectID != t.plan.Material.ProjectID {
		return ErrAuthentication
	}
	if err := t.rejectActiveJournals(); err != nil {
		return err
	}
	if err := t.recheckLockedMaterial(m); err != nil {
		return err
	}
	for name, before := range m.Before {
		after, ok := m.After[name]
		if (!ok && (t.plan.Kind != NativeUpdateKind || before.Directory)) || before.Directory && !sameFile(before, after) {
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

func (t *Transaction) prepare(ctx context.Context, m Material) error {
	fail := func(err error) error { return err }
	var err error
	kind := t.plan.Kind
	if err := privateDirectory(t.dir); err != nil {
		return fail(err)
	}
	if err := t.writeSigned("plan.json", t.plan, true); err != nil {
		return fail(err)
	}
	if err := privateDirectory(t.images); err != nil {
		return fail(err)
	}
	imageInfo, err := confinedLstat(t.images)
	if err != nil {
		return fail(err)
	}
	t.state = progress{ImageIdentity: fileID(imageInfo), APIVersion: APIVersion, Kind: kind, ID: t.plan.ID, Fingerprint: m.Fingerprint, Phase: "preparing", Steps: []step{}}
	if err := t.save(); err != nil {
		return fail(err)
	}
	t.durable = true
	receiptInfo, err := confinedLstat(t.dir)
	if err != nil {
		return err
	}
	t.state.ReceiptIdentity = fileID(receiptInfo)
	steps := t.expectedSteps()
	for i, s := range steps {
		s.Slot = fmt.Sprintf("%06d", i)
		before, after, _ := t.stepFiles(s)
		if s.Delete {
			s.AfterIdentity = Identity{before.Device, before.Inode}
		} else {
			pathname := t.slotPath(s)
			if after.Directory {
				err = stageDirectory(ctx, pathname, os.FileMode(after.Mode))
			} else {
				err = durableExclusive(pathname, after.Data, os.FileMode(after.Mode))
			}
			if err != nil {
				return err
			}
			info, e := confinedLstat(pathname)
			if e != nil {
				return e
			}
			s.AfterIdentity = fileID(info)
		}
		t.state.Steps = append(t.state.Steps, s)
		if err := t.save(); err != nil {
			return err
		}
	}
	t.state.Phase = "prepared"
	if err := t.save(); err != nil {
		return fail(err)
	}
	return nil
}

// OpenNative authenticates both journal records with an internal runtime-owned
// seal, then reloads actual installed identity/source and rebuilds the immutable
// fingerprint. A caller cannot supply a MAC key or trusted recovery callback.
func Open(ctx context.Context, runtime *trustload.Runtime, kind, home, id string) (*Transaction, error) {
	if len(id) != 32 {
		return nil, ErrAuthentication
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, ErrAuthentication
	}
	if runtime == nil || runtime.TrustRuntime() == nil {
		return nil, ErrAuthentication
	}
	pc := runtime.ProjectContext()
	key, err := runtimeKey(ctx, runtime, pc.ProjectID, false)
	if err != nil {
		return nil, err
	}
	t := &Transaction{runtime: runtime, key: key, dir: journalDir(home, id), plan: immutable{Kind: kind}}
	fail := func(err error) (*Transaction, error) { t.Release(); return nil, err }
	if err := t.readSigned("plan.json", &t.plan); err != nil {
		return fail(err)
	}
	if t.plan.APIVersion != APIVersion || t.plan.Kind != kind || t.plan.ID != id || t.plan.Material.Home != home || t.plan.Material.Root != pc.RootPath {
		return fail(ErrAuthentication)
	}
	t.images = filepath.Join(pc.RootPath, ".tplaiter", "project-transactions", id)
	if err := t.readSigned("state.json", &t.state); err != nil {
		return fail(err)
	}
	if t.state.APIVersion != APIVersion || t.state.Kind != kind || t.state.ID != id || t.state.Fingerprint != t.plan.Material.Fingerprint {
		return fail(ErrAuthentication)
	}
	lease, err := acquireLease(runtime, pc.RootPath)
	if err != nil {
		return fail(err)
	}
	t.lease = lease
	if err := t.authenticate(ctx); err != nil {
		return fail(err)
	}
	if err := t.acquireWriterLocks(); err != nil {
		return fail(err)
	}
	if err := t.authenticate(ctx); err != nil {
		return fail(err)
	}
	if err := t.readonlyBindings(); err != nil {
		return fail(err)
	}
	if err := t.validateSteps(); err != nil {
		return fail(err)
	}
	t.durable = true
	return t, nil
}

func (t *Transaction) authenticate(ctx context.Context) error {
	for _, f := range t.writerLocks {
		held, err := f.Stat()
		actual, other := confinedLstat(f.Name())
		if err != nil || other != nil || !os.SameFile(held, actual) || !singleLink(actual) {
			return ErrConflict
		}
	}
	if ctx == nil {
		return ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m := t.plan.Material
	if t.runtime == nil || t.runtime.TrustRuntime() == nil || !t.runtime.TrustRuntime().Binding().Equal(m.Binding) || t.runtime.ProjectContext().RootPath != m.Root {
		return ErrAuthentication
	}
	if err := t.runtime.TrustRuntime().CheckProjectIdentity(ctx, m.Root, m.ProjectID); err != nil {
		return err
	}
	homeInfo, homeErr := confinedLstat(t.plan.Material.Home)
	if homeErr != nil || !homeInfo.IsDir() || fileID(homeInfo) != t.plan.HomeIdentity {
		return ErrConflict
	}
	info, err := confinedLstat(t.plan.Material.Root)
	if err != nil || fileID(info) != t.plan.RootIdentity || !info.IsDir() {
		return ErrConflict
	}
	return nil
}

func (t *Transaction) validateSteps() error {
	expected := t.expectedSteps()
	partial := t.state.Phase == "preparing" || t.state.Phase == "rolling-back" || t.state.Phase == "rollback-conflicts" || t.state.Phase == "rolled-back"
	if t.state.ImageIdentity.Inode == 0 || len(t.state.Steps) > len(expected) || (!partial && len(expected) != len(t.state.Steps)) {
		return ErrAuthentication
	}
	for i, s := range t.state.Steps {
		e := expected[i]
		if s.Path != e.Path || s.Delete != e.Delete || s.Registry != e.Registry || s.Slot != fmt.Sprintf("%06d", i) || s.AfterIdentity.Inode == 0 {
			return ErrAuthentication
		}
	}
	return nil
}

// Apply is resumable after a killed process. Atomic exchanges keep exact original
// inodes in owned slots. Intent is sealed before publication; cold reconciliation
// distinguishes both sides of that boundary without adopting ambient bytes.
func (t *Transaction) Apply(ctx context.Context) error {
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
	if t.plan.Kind == NativeUpdateKind && t.state.Phase == "preparing" {
		if err := t.authenticate(ctx); err != nil {
			return err
		}
		return ErrPreparingContinue
	}
	if t.state.Phase != "prepared" && t.state.Phase != "applying" {
		return ErrAuthentication
	}
	if err := t.authenticate(ctx); err != nil {
		if t.state.Phase == "applying" {
			return t.rollbackAfter(err)
		}
		return err
	}
	t.state.Phase = "applying"
	if err := t.save(); err != nil {
		return err
	}
	for i := range t.state.Steps {
		if err := ctx.Err(); err != nil {
			return t.rollbackAfter(err)
		}
		if err := t.authenticate(ctx); err != nil {
			return t.rollbackAfter(err)
		}
		if err := t.checkObservations(ctx); err != nil {
			return t.rollbackAfter(err)
		}
		if err := t.applyStep(ctx, i); err != nil {
			return t.rollbackAfter(err)
		}
	}
	return nil
}

func (t *Transaction) Commit(ctx context.Context) error {
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
		return t.rollbackAfter(err)
	}
	if t.plan.Kind == NativeUpdateKind {
		if err := t.checkObservations(ctx); err != nil {
			return t.rollbackAfter(err)
		}
	}
	if err := t.readonlyBindings(); err != nil {
		return t.rollbackAfter(err)
	}
	for _, step := range t.state.Steps {
		if err := t.checkStepFinal(step); err != nil {
			return t.rollbackAfter(err)
		}
	}
	terminal := t.state
	terminal.Steps = append([]step{}, t.state.Steps...)
	terminal.Phase = "committed"
	// The live phase changes only after a successful durable publication.
	if err := t.writeSigned("state.json", terminal, false); err != nil {
		var published *publishedWriteError
		if errors.As(err, &published) {
			t.pendingCommit = &terminal
		}
		return err
	}
	t.state = terminal
	return nil
}

func (t *Transaction) confirmCommit(ctx context.Context) error {
	if t.lease == nil || !t.admitted {
		return ErrActive
	}
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	expected := t.state
	if t.pendingCommit != nil {
		expected = *t.pendingCommit
	}
	var actual progress
	if err := t.readSigned("state.json", &actual); err != nil {
		return err
	}
	want, err := canonicaljson.Canonical(expected)
	if err != nil {
		return err
	}
	got, err := canonicaljson.Canonical(actual)
	if err != nil || actual.Phase != "committed" || !bytes.Equal(want, got) {
		return ErrAuthentication
	}
	// File sync preceded rename. Sync the actual authenticated receipt again
	// and its directory so a prior published/fsync-uncertain result is resolved.
	if err := syncReceipt(filepath.Join(t.dir, "state.json")); err != nil {
		return err
	}
	t.state = actual
	t.pendingCommit = nil
	return nil
}

func (t *Transaction) Rollback(ctx context.Context) error {
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
	return t.rollback()
}

// Terminal retries authenticate and durably confirm the actual bound receipt,
// including fresh handles loaded after uncertain terminal publication.
func (t *Transaction) confirmRollback() error {
	if t.lease == nil || !t.admitted {
		return ErrActive
	}
	var actual progress
	if err := t.readSigned("state.json", &actual); err != nil {
		return err
	}
	want, err := canonicaljson.Canonical(t.state)
	if err != nil {
		return err
	}
	got, err := canonicaljson.Canonical(actual)
	if err != nil || actual.Phase != "rolled-back" || !bytes.Equal(want, got) {
		return ErrAuthentication
	}
	sealed, err := t.signedBytes("state.json", actual)
	if err != nil {
		return err
	}
	if err := syncReceiptExact(filepath.Join(t.dir, "state.json"), sealed, t.rollbackSyncFault); err != nil {
		return err
	}
	t.state = actual
	return nil
}

func (t *Transaction) rollbackAfter(cause error) error { return errors.Join(cause, t.rollback()) }
func (t *Transaction) rollback() error {
	if t.pendingCommit != nil {
		return ErrCommitUncertain
	}
	if t.state.Phase == "committed" {
		return ErrAuthentication
	}
	if t.state.Phase == "rolled-back" {
		return t.confirmRollback()
	}
	t.state.Phase = "rolling-back"
	if err := t.save(); err != nil {
		return err
	}
	var failures []error
	for i := len(t.state.Steps) - 1; i >= 0; i-- {
		if err := t.undoStep(i); err != nil {
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
	persistErr := t.writeSigned("state.json", terminal, false)
	if persistErr == nil {
		t.state = terminal
	}
	return errors.Join(errors.Join(failures...), persistErr)
}

func (t *Transaction) applyStep(ctx context.Context, i int) error {
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
		return t.save()
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
	if err := t.save(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.publish(*s, exists); err != nil {
		return err
	}
	if exists && checkPath(t.slotPath(*s), before, Identity{before.Device, before.Inode}) != nil {
		// A foreign replacement raced the exchange. Put that exact inode back only
		// while the destination still contains our prepared inode.
		if t.checkTarget(*s, after, s.AfterIdentity) == nil {
			_ = t.publish(*s, true)
		}
		return ErrConflict
	}
	if err := t.checkTarget(*s, after, s.AfterIdentity); err != nil {
		return err
	}
	s.Done = true
	return t.save()
}

func (t *Transaction) undoStep(i int) error {
	s := &t.state.Steps[i]
	if s.Undone {
		return nil
	}
	if s.Delete {
		return t.undoDelete(i)
	}
	before, after, existed := t.stepFiles(*s)
	target := t.targetPath(*s)
	slot := t.slotPath(*s)
	// A step not published (or already reverted before a crash) needs no write.
	if existed && t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil && checkPath(slot, after, s.AfterIdentity) == nil {
		s.Undone = true
		return t.save()
	}
	if !existed {
		if _, err := confinedLstat(target); os.IsNotExist(err) && checkPath(slot, after, s.AfterIdentity) == nil {
			s.Undone = true
			return t.save()
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
		if err := t.publish(*s, true); err != nil {
			return err
		}
		if checkPath(slot, after, s.AfterIdentity) != nil { // Undo encountered a raced foreign inode; restore it.
			if t.checkTarget(*s, before, Identity{before.Device, before.Inode}) == nil {
				_ = t.publish(*s, true)
			}
			return ErrConflict
		}
	} else {
		if err := t.quarantine(*s); err != nil {
			return err
		}
		if checkPath(slot, after, s.AfterIdentity) != nil {
			_ = t.publish(*s, false)
			return ErrConflict
		}
	}
	s.Undone = true
	return t.save()
}

func (t *Transaction) checkTarget(s step, file File, id Identity) error {
	if err := t.checkNamespace(s); err != nil {
		return err
	}
	if s.Registry {
		return checkPath(t.targetPath(s), file, id)
	}
	if err := t.checkParents(s.Path); err != nil {
		return err
	}
	return checkPath(filepath.Join(t.plan.Material.Root, s.Path), file, id)
}

func (t *Transaction) checkParents(name string) error {
	if !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\n\x00") {
		return ErrConflict
	}
	for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
		info, err := confinedLstat(filepath.Join(t.plan.Material.Root, parent))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrConflict
		}
		if original, ok := t.plan.Material.Before[filepath.ToSlash(parent)]; ok {
			if fileID(info) != (Identity{original.Device, original.Inode}) {
				return ErrConflict
			}
		} else {
			found := false
			for _, s := range t.state.Steps {
				if s.Path == filepath.ToSlash(parent) && s.AfterIdentity == fileID(info) {
					found = true
				}
			}
			if !found {
				return ErrConflict
			}
		}
	}
	return nil
}

func sameFile(a, b File) bool {
	return a.Directory == b.Directory && a.Mode == b.Mode && bytes.Equal(a.Data, b.Data)
}

func checkPath(name string, file File, id Identity) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return ErrConflict
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || fileID(info) != id || info.Mode().Perm() != os.FileMode(file.Mode) || info.IsDir() != file.Directory {
		return ErrConflict
	}
	if file.Directory {
		if checkStorageParent(root, name) != nil {
			return ErrConflict
		}
		return nil
	}
	if !singleLink(info) {
		return ErrConflict
	}
	f, err := root.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return ErrConflict
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return ErrConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if err != nil || !bytes.Equal(raw, file.Data) || checkStorageParent(root, name) != nil {
		return ErrConflict
	}
	return nil
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) || strings.HasPrefix(b, a+string(os.PathSeparator))
}

func journalDir(home, id string) string {
	return filepath.Join(home, "transactions", "project", "tx-"+id)
}
func (t *Transaction) save() error { return t.writeSigned("state.json", t.state, false) }
func (t *Transaction) signedBytes(name string, value any) ([]byte, error) {
	raw, err := canonicaljson.Canonical(value)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, t.key)
	mac.Write([]byte(APIVersion + "\x00" + t.plan.Kind + "\x00" + t.dir + "\x00" + name + "\x00"))
	mac.Write(raw)
	data, err := canonicaljson.Canonical(envelope{Payload: raw, MAC: hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return nil, err
	}
	if len(data) > 128<<20 {
		return nil, ErrAuthentication
	}
	return data, nil
}

func (t *Transaction) writeSigned(name string, value any, exclusive bool) error {
	data, err := t.signedBytes(name, value)
	if err != nil {
		return err
	}
	if exclusive {
		return durableExclusive(filepath.Join(t.dir, name), data, 0o600)
	}
	fault := commitWriteOK
	if state, ok := value.(progress); ok && name == "state.json" {
		switch state.Phase {
		case "committed":
			fault = t.commitFault
		case "rolled-back":
			fault = t.rollbackFault
		}
	}
	return durableReplace(filepath.Join(t.dir, name), data, fault)
}

func (t *Transaction) readSigned(name string, value any) error {
	data, err := privateRead(filepath.Join(t.dir, name), 128<<20)
	if err != nil {
		return err
	}
	var record envelope
	if err := canonicaljson.DecodeStrict(data, &record); err != nil {
		return fmt.Errorf("%w: envelope: %w", ErrAuthentication, err)
	}
	mac := hmac.New(sha256.New, t.key)
	mac.Write([]byte(APIVersion + "\x00" + t.plan.Kind + "\x00" + t.dir + "\x00" + name + "\x00"))
	mac.Write(record.Payload)
	actual, err := hex.DecodeString(record.MAC)
	if err != nil || !hmac.Equal(actual, mac.Sum(nil)) {
		return ErrAuthentication
	}
	if err := canonicaljson.DecodeStrict(record.Payload, value); err != nil {
		return fmt.Errorf("%w: payload: %w", ErrAuthentication, err)
	}
	return nil
}

// Fixed project/source bindings are read-only throughout application. Their
// bytes/modes/inodes must still match the authenticated original observation.
func (t *Transaction) readonlyBindings() error {
	for name, file := range t.plan.Material.Before {
		if slices.Contains(t.plan.Material.ReadOnlyPaths, name) {
			if err := checkPath(filepath.Join(t.plan.Material.Root, name), file, Identity{file.Device, file.Inode}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reobserve the complete captured permutation before every mutation. Completed
// paths must carry our exact prepared inode; future/unchanged paths must still
// carry their exact original inode, bytes and mode. This is not ledger adoption.
func (t *Transaction) checkObservations(ctx context.Context) error {
	steps := map[string]step{}
	for _, s := range t.state.Steps {
		if !s.Registry {
			steps[s.Path] = s
		}
	}
	for name, original := range t.plan.Material.Before {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s, ok := steps[name]; ok && s.Delete {
			if s.Done || (s.Intent && t.checkDeleted(s) == nil) {
				if err := t.checkDeleted(s); err != nil {
					return err
				}
				continue
			}
		}
		want := original
		id := Identity{original.Device, original.Inode}
		if s, ok := steps[name]; ok && (s.Done || s.Intent && t.checkTarget(s, t.plan.Material.After[name], s.AfterIdentity) == nil) {
			want = t.plan.Material.After[name]
			id = s.AfterIdentity
		}
		if err := checkPath(filepath.Join(t.plan.Material.Root, name), want, id); err != nil {
			return err
		}
	}
	for name, after := range t.plan.Material.After {
		if _, ok := t.plan.Material.Before[name]; ok {
			continue
		}
		s, ok := steps[name]
		if !ok {
			return ErrAuthentication
		}
		if s.Done || s.Intent && t.checkTarget(s, after, s.AfterIdentity) == nil {
			if err := t.checkTarget(s, after, s.AfterIdentity); err != nil {
				return err
			}
		} else if _, err := confinedLstat(filepath.Join(t.plan.Material.Root, name)); !os.IsNotExist(err) {
			return ErrConflict
		}
	}
	if err := t.checkRegistryObservation(); err != nil {
		return err
	}
	return t.readonlyBindings()
}

// Admission is a trusted adapter operation, unavailable to imports outside
// projecttransaction. It never accepts a boolean or callback claiming trust.
func (t *Transaction) Admit(ctx context.Context) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if err := t.readonlyBindings(); err != nil {
		return err
	}
	t.admitted = true
	return nil
}

func (t *Transaction) Material() Material {
	raw, _ := canonicaljson.Canonical(t.plan.Material)
	var out Material
	_ = canonicaljson.DecodeStrict(raw, &out)
	return out
}

func (t *Transaction) recheckLockedMaterial(fresh Material) error {
	if err := t.sameRegistryMaterial(fresh); err != nil {
		return err
	}
	old := t.plan.Material
	for name, file := range old.Before {
		actual, ok := fresh.Before[name]
		if !ok || !sameFile(file, actual) || file.Device != actual.Device || file.Inode != actual.Inode {
			return ErrConflict
		}
	}
	for name, file := range fresh.Before {
		if _, ok := old.Before[name]; ok {
			continue
		}
		if name != ".tplaiter/update.lock" || file.Directory || file.Mode != 0o600 || len(file.Data) != 0 {
			return ErrConflict
		}
		found := false
		for _, f := range t.writerLocks {
			if f.Name() == filepath.Join(fresh.Root, name) {
				info, err := f.Stat()
				if err == nil && fileID(info) == (Identity{file.Device, file.Inode}) {
					found = true
				}
			}
		}
		if !found {
			return ErrConflict
		}
	}
	for name, file := range old.After {
		actual, ok := fresh.After[name]
		if !ok || !sameFile(file, actual) {
			return ErrConflict
		}
	}
	for name := range fresh.After {
		if _, ok := old.After[name]; !ok && name != ".tplaiter/update.lock" {
			return ErrConflict
		}
	}
	return nil
}

// ValidateLocked is restricted to the concrete adapter by the nested internal
// boundary. It proves the exact post-lease control image before durable staging.
func (t *Transaction) ValidateLocked(ctx context.Context, m Material) error {
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if err := t.recheckLockedMaterial(m); err != nil {
		return err
	}
	return t.checkRegistryMaterial(m)
}

func (t *Transaction) CheckedMaterial() (Material, error) {
	raw, err := canonicaljson.Canonical(t.plan.Material)
	if err != nil {
		return Material{}, err
	}
	var out Material
	err = canonicaljson.DecodeStrict(raw, &out)
	return out, err
}
