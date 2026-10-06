// Package newtransaction owns the global, cross-project transaction used by
// `new`.  It deliberately stores the journal outside the target tree: a
// target which has not been published yet must still be recoverable.
package newtransaction

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/naming"
	"github.com/tplAIter/tplaiter/internal/newtransaction/inspect"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Schema is the recovery-manifest schema version.
const Schema = 1

// Wire identities. The journal and lock formats are closed: an unknown
// apiVersion is reported as a future version and never reinterpreted.
const (
	APIVersion     = "tplaiter.dev/new-transaction/v1"
	LockAPIVersion = "tplaiter.dev/new-lock/v1"
	commitDomain   = "tplaiter.dev/new-transaction/commit/v1"
	stagingInfix   = ".tplaiter-new-"
	// apiVersionFamily prefixes every journal wire version, current or future.
	apiVersionFamily = "tplaiter.dev/new-transaction/"
)

// pendingMarkerRel is the marker path inside a staged or published target.
var pendingMarkerRel = filepath.Join(naming.ProjectDir, ledgerpath.NewPendingMarker)

var (
	ErrActive        = errors.New("new transaction: active transaction exists")
	ErrNoActive      = inspect.ErrNoActive
	ErrCommitted     = errors.New("new transaction: transaction is committed")
	ErrUnsafe        = inspect.ErrUnsafe
	ErrInjectedCrash = errors.New("new transaction: injected crash")
	// ErrFutureVersion reports a journal written by a newer wire version. It
	// is preserved as evidence and never reinterpreted.
	ErrFutureVersion = inspect.ErrFutureVersion
	// ErrMissingCAS reports a journal whose content-addressed evidence is
	// absent. The journal is preserved; recovery refuses to guess.
	ErrMissingCAS = inspect.ErrMissingCAS
)

// UnsupportedHookError is returned before commit when a hook kind cannot be
// safely reconstructed by a later recovery process.
type UnsupportedHookError struct{ Kind string }

func (e UnsupportedHookError) Error() string {
	return fmt.Sprintf("new transaction: hook kind %q cannot be recovered safely", e.Kind)
}

type Phase = inspect.Phase

const (
	Prepared     = inspect.Prepared
	Publishing   = inspect.Publishing
	Committed    = inspect.Committed
	HooksRunning = inspect.HooksRunning
	HooksFailed  = inspect.HooksFailed
	Complete     = inspect.Complete
	Aborted      = inspect.Aborted
)

type RegistryPlan struct {
	Home          string
	Before, After []byte
}

type (
	HookEntry    = inspect.HookEntry
	HookProgress = inspect.HookProgress
)

type (
	HookExecutor  func(context.Context, HookEntry) error
	FaultInjector func(point string) error
)

type (
	Journal          = inspect.Journal
	recoveryManifest = inspect.Manifest
)

func nullableDigest(value string) *string {
	if value == "" {
		return nil
	}
	cp := value
	return &cp
}

func derefDigest(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (t *Transaction) PrepareHooks(plan []HookEntry) error {
	if t == nil || t.j.Phase != Prepared {
		return ErrUnsafe
	}
	if t.sealedTree != "" && len(plan) != 0 {
		return ErrUnsafe
	}
	for i := range plan {
		if plan[i].Kind == "" || plan[i].Command == "" {
			return ErrUnsafe
		}
		if plan[i].Kind != "shell" {
			return UnsupportedHookError{Kind: plan[i].Kind}
		}
		if plan[i].Digest == "" {
			plan[i].Digest = hookDigest(plan[i])
		}
		if plan[i].Digest != hookDigest(plan[i]) {
			return ErrUnsafe
		}
	}
	t.j.Hooks = HookProgress{Plan: append([]HookEntry(nil), plan...)}
	return t.save()
}

type Transaction struct {
	home, dir        string
	j                Journal
	fault            FaultInjector
	lock             *os.File // global new.lock, held from Begin through publication
	sealedTree       string
	sealedReady      bool
	managedReference *formatproof.PublicationReference
	managedRuntime   *trustload.Runtime
}

func Begin(home, target string) (*Transaction, error) {
	return begin(home, target, nil, "")
}

// BeginWithFault is a deterministic crash-injection seam for boundary tests;
// production callers use Begin and therefore have no fault dependency.
func BeginWithFault(home, target string, fault FaultInjector) (*Transaction, error) {
	return begin(home, target, fault, "")
}

func begin(home, target string, fault FaultInjector, sealedTree string) (*Transaction, error) {
	if home == "" || target == "" {
		return nil, errors.New("new transaction: home and target are required")
	}
	var err error
	home, err = absClean(home)
	if err != nil {
		return nil, err
	}
	target, err = absClean(target)
	if err != nil {
		return nil, err
	}
	if err := rejectSymlinkParents(filepath.Dir(target)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("new transaction: target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: target must be a real directory", ErrUnsafe)
	}
	if err := rejectSymlinkStateDir(target); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	lock, err := acquireNewLock(filepath.Join(home, filepath.FromSlash(ledgerpath.NewLock)), id)
	if err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			_ = lock.Close()
		}
	}()
	root := filepath.Join(home, filepath.FromSlash(ledgerpath.NewTransactionsDir))
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "tx-"+id)
	// Keep the staged tree next to its final path: home and target may live on
	// different filesystems, while directory publication must remain a
	// same-filesystem rename. Only the journal and CAS live under the home.
	staging := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+stagingInfix+id)
	if _, err := os.Lstat(staging); err == nil {
		return nil, fmt.Errorf("%w: staging path already exists", ErrUnsafe)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tx := &Transaction{home: home, dir: dir, fault: fault, lock: lock, j: Journal{APIVersion: APIVersion, Schema: Schema, ID: id, Phase: Prepared, Target: target, Staging: staging, TargetExisted: true, PendingMarker: pendingMarkerRel, CreatedAt: now, UpdatedAt: now}}
	tx.sealedTree = sealedTree
	// The before image is captured while the target is still in place.
	beforeTree, err := snapshotTree(target)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	tx.j.TargetBeforeTreeSHA = digest(beforeTree)
	if err := tx.saveCASBlob(tx.j.TargetBeforeTreeSHA, beforeTree); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := tx.inject("begin.before_journal"); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	// The prepared journal is durable before the target moves. A crash at any
	// later point leaves a journal that AbortByID uses to restore the target.
	if err := tx.save(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := tx.inject("begin.after_journal"); err != nil {
		return nil, err
	}
	// Recheck under the held lock after the journal boundary. An uncooperative
	// writer is not part of the captured beforeimage and must never be erased.
	if tx.sealedTree != "" {
		fresh, captureErr := snapshotTree(target)
		if captureErr != nil || digest(fresh) != tx.j.TargetBeforeTreeSHA {
			return nil, ErrOwnershipUncertain
		}
		if len(fresh) != 0 {
			return nil, ErrOwnershipUncertain
		}
	}
	fail := func(cause error) (*Transaction, error) {
		if abortErr := tx.abortLocked(); abortErr != nil {
			return nil, errors.Join(cause, abortErr)
		}
		return nil, cause
	}
	if err := os.Rename(target, staging); err != nil {
		return fail(fmt.Errorf("new transaction: stage target: %w", err))
	}
	if err := tx.inject("begin.after_stage"); err != nil {
		return nil, err
	}
	if tx.sealedTree != "" {
		fresh, captureErr := snapshotTree(staging)
		if captureErr != nil || digest(fresh) != tx.j.TargetBeforeTreeSHA {
			return nil, ErrOwnershipUncertain
		}
	}
	pendingDir, err := transactionDir(staging, true)
	if err != nil {
		return fail(fmt.Errorf("new transaction: create pending directory: %w", err))
	}
	pending := filepath.Join(pendingDir, filepath.Base(pendingMarkerRel))
	if _, err := os.Lstat(pending); err == nil {
		return fail(fmt.Errorf("%w: pending marker already exists", ErrUnsafe))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fail(err)
	}
	marker, err := json.Marshal(map[string]string{"transactionID": id, "phase": "pending"})
	if err != nil {
		return fail(err)
	}
	if err := writeFileDurable(pending, marker); err != nil {
		return fail(err)
	}
	if err := tx.inject("begin.after_marker"); err != nil {
		return nil, err
	}
	if err := tx.save(); err != nil {
		return fail(fmt.Errorf("new transaction: persist staged manifest: %w", err))
	}
	release = false
	return tx, nil
}

func Load(home, id string) (*Transaction, error) {
	record, err := inspect.Load(home, id)
	if err != nil {
		return nil, err
	}
	manifest := record.Manifest()
	return &Transaction{home: record.Home(), dir: record.Directory(), j: record.Journal(), sealedTree: manifest.SealedTree, sealedReady: manifest.SealedReady, managedReference: manifest.ManagedPublication}, nil
}

func (t *Transaction) ID() string        { return t.j.ID }
func (t *Transaction) Workspace() string { return t.j.Staging }
func (t *Transaction) Journal() Journal  { return t.j }

func (t *Transaction) PrepareRegistry(plan RegistryPlan) error {
	if err := t.checkManaged(context.Background(), false, &plan); err != nil {
		return err
	}
	if t == nil || t.j.Phase != Prepared {
		return ErrUnsafe
	}
	if t.sealedTree != "" && !t.sealedReady {
		return ErrOwnershipUncertain
	}
	if plan.Home == "" {
		return errors.New("new transaction: registry home is required")
	}
	home, err := absClean(plan.Home)
	if err != nil {
		return err
	}
	if t.j.RegistryTarget != "" && t.j.RegistryTarget != state.ProjectsPath(home) {
		return ErrUnsafe
	}
	var current []byte
	var exists bool
	if err := state.WithLock(home, func() error {
		var err error
		current, exists, _, err = state.ReadProjectsRaw(home)
		return err
	}); err != nil {
		return err
	}
	if !exists {
		current = nil
	}
	if digest(current) != digest(plan.Before) {
		return fmt.Errorf("%w: registry preimage changed", ErrUnsafe)
	}
	if _, err := state.DecodeProjectsRaw(plan.Before); err != nil && len(plan.Before) != 0 {
		return err
	}
	if _, err := state.DecodeProjectsRaw(plan.After); err != nil {
		return err
	}
	t.j.RegistryTarget = state.ProjectsPath(home)
	t.j.RegistryBeforeSHA = digest(plan.Before)
	t.j.RegistryAfterSHA = digest(plan.After)
	return t.saveCAS(plan.Before, plan.After)
}

func (t *Transaction) Commit(plan RegistryPlan) error {
	if err := t.checkManaged(context.Background(), true, &plan); err != nil {
		return err
	}
	if t == nil {
		return ErrUnsafe
	}
	if err := t.acquireGlobalLock(); err != nil {
		return err
	}
	// Once publication is attempted, an incomplete journal—not a process-held
	// lock—is the recovery authority.  Releasing on every return avoids
	// wedging subsequent operations after a returned crash/fault error.
	defer t.releaseGlobalLock()
	if t.j.Phase == Committed || t.j.Phase == Complete {
		return ErrCommitted
	}
	if t.j.Phase != Prepared && t.j.Phase != Publishing {
		return ErrUnsafe
	}
	if t.sealedTree != "" && !t.sealedReady {
		return ErrOwnershipUncertain
	}
	home, err := absClean(plan.Home)
	if err != nil || home == "" || t.j.RegistryTarget != state.ProjectsPath(home) ||
		digest(plan.Before) != t.j.RegistryBeforeSHA || digest(plan.After) != t.j.RegistryAfterSHA {
		return ErrUnsafe
	}
	t.j.Phase = Publishing
	if err := t.inject("commit.before_journal"); err != nil {
		return err
	}
	if err := t.save(); err != nil {
		return err
	}
	if _, err := os.Lstat(t.j.Target); os.IsNotExist(err) {
		if err := t.inject("commit.before_staging_publish"); err != nil {
			return err
		}
		if t.sealedTree != "" {
			if err := t.verifySealedTree(t.j.Staging); err != nil {
				return err
			}
		}
		if err := os.Rename(t.j.Staging, t.j.Target); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		return ErrUnsafe
	}
	if err := t.verifyPending(); err != nil {
		return err
	}
	if err := t.inject("commit.after_staging_publish"); err != nil {
		return err
	}
	if err := t.inject("commit.before_registry"); err != nil {
		return err
	}
	if t.sealedTree != "" {
		if err := t.verifySealedTree(t.j.Target); err != nil {
			return err
		}
	}
	if err := state.WithLock(home, func() error {
		current, exists, _, err := state.ReadProjectsRaw(home)
		if err != nil {
			return err
		}
		if !exists {
			current = nil
		}
		if digest(current) != t.j.RegistryBeforeSHA {
			return fmt.Errorf("%w: registry changed during publish", ErrUnsafe)
		}
		if t.sealedTree != "" {
			if err := t.verifySealedTree(t.j.Target); err != nil {
				return err
			}
		}
		return state.WriteProjectsRaw(home, plan.After, 0o600)
	}); err != nil {
		return err
	}
	if err := t.inject("commit.after_registry"); err != nil {
		return err
	}
	if t.sealedTree != "" {
		if err := t.verifySealedTree(t.j.Target); err != nil {
			return err
		}
	}
	// The durable COMMITTED record is the linearization point.  Keep the
	// pending marker until it has been persisted: a crash must never expose a
	// registry entry and target with neither marker nor recoverable commit.
	t.j.Phase = Committed
	record := commitRecordDigest(t.j.TargetAfterSHA, t.j.RegistryAfterSHA)
	t.j.CommitRecordSHA256 = &record
	if err := t.save(); err != nil {
		return err
	}
	if err := t.inject("commit.before_marker_remove"); err != nil {
		return err
	}
	if t.sealedTree != "" {
		if err := t.verifySealedTree(t.j.Target); err != nil {
			return err
		}
	}
	if err := t.removePending(); err != nil {
		return err
	}
	if err := t.verifyTargetAfter(); err != nil {
		return err
	}
	if err := t.inject("commit.after_marker_remove"); err != nil {
		return err
	}
	return nil
}

// Finalize removes a committed journal only after all durable hook progress
// has reached the end. It is safe to call repeatedly.
func (t *Transaction) Finalize() error {
	if t == nil || t.j.Phase != Committed {
		return ErrUnsafe
	}
	hookLock, err := acquireExisting(filepath.Join(t.dir, "hooks.lock"))
	if err != nil {
		return err
	}
	defer func() { _ = hookLock.Close() }()
	if err := t.refresh(); err != nil {
		return err
	}
	if err := t.checkManaged(context.Background(), false, nil); err != nil {
		return err
	}
	if t.j.Hooks.Next != len(t.j.Hooks.Plan) {
		return errors.New("new transaction: hooks are still pending")
	}
	if err := t.inject("finalize.before_journal"); err != nil {
		return err
	}
	if t.sealedTree != "" {
		if err := t.verifySealedTree(t.j.Target); err != nil {
			return err
		}
	}
	t.j.Phase = Complete
	if err := t.save(); err != nil {
		return err
	}
	return os.RemoveAll(t.dir)
}

func (t *Transaction) Abort() error {
	if t == nil {
		return ErrUnsafe
	}
	if err := t.acquireGlobalLock(); err != nil {
		return err
	}
	defer t.releaseGlobalLock()
	return t.abortLocked()
}

func (t *Transaction) abortLocked() error {
	if err := t.checkManaged(context.Background(), false, nil); err != nil {
		return err
	}
	if t.j.Phase != Prepared {
		return ErrCommitted
	}
	_, targetErr := os.Lstat(t.j.Target)
	_, stagingErr := os.Lstat(t.j.Staging)
	switch {
	case stagingErr == nil && errors.Is(targetErr, fs.ErrNotExist):
		if t.sealedTree != "" {
			if err := t.verifySealedAbort(); err != nil {
				return err
			}
		}
		if err := t.removePendingFromStaging(); err != nil {
			return err
		}
		if err := t.restoreBeforeTree(); err != nil {
			return err
		}
		if err := os.Rename(t.j.Staging, t.j.Target); err != nil {
			return err
		}
	case errors.Is(stagingErr, fs.ErrNotExist) && targetErr == nil:
		// Only a process that stopped before the target was staged leaves
		// this shape. A target that already carries this transaction's
		// pending marker, or no longer matches the journaled before image,
		// was published by someone: deleting the journal would strand the
		// rendered files, so the journal is kept for inspection instead.
		if err := t.verifyTargetUnstaged(); err != nil {
			if t.sealedTree != "" {
				return errors.Join(ErrOwnershipUncertain, err)
			}
			return err
		}
	default:
		return ErrUnsafe
	}
	t.j.Phase = Aborted
	_ = t.save()
	return os.RemoveAll(t.dir)
}

// verifyTargetUnstaged proves that a prepared transaction never moved its
// target: no pending marker for this transaction exists there and the tree is
// byte-for-byte the journaled before image.
func (t *Transaction) verifyTargetUnstaged() error {
	// A missing state directory means no marker; any other shape is checked
	// by transactionDir, which refuses symlinks and non-directories.
	if _, err := os.Lstat(filepath.Join(t.j.Target, naming.ProjectDir)); err == nil {
		pendingDir, err := transactionDir(t.j.Target, false)
		if err != nil {
			return err
		}
		marker := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
		if _, err := os.Lstat(marker); err == nil {
			return fmt.Errorf("%w: target already holds the pending marker", ErrUnsafe)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	snapshot, err := snapshotTree(t.j.Target)
	if err != nil {
		return err
	}
	if digest(snapshot) != t.j.TargetBeforeTreeSHA {
		return fmt.Errorf("%w: target differs from the journaled before image", ErrUnsafe)
	}
	return nil
}

// RunHooks is an at-least-once executor. A crash before the checkpoint retries
// the current entry; completed entries are never replayed. Mandatory failure
// remains committed and retryable, preserving the target/registry boundary.
func (t *Transaction) RunHooks(ctx context.Context, exec HookExecutor) error {
	if t == nil || (t.j.Phase != Committed && t.j.Phase != HooksRunning && t.j.Phase != HooksFailed) {
		return ErrUnsafe
	}
	if exec == nil {
		return errors.New("new transaction: hook executor is required")
	}
	for _, entry := range t.j.Hooks.Plan {
		if entry.Kind != "shell" || entry.Command == "" || entry.Digest != hookDigest(entry) {
			return ErrUnsafe
		}
	}
	hookLock, err := acquireExisting(filepath.Join(t.dir, "hooks.lock"))
	if err != nil {
		return err
	}
	defer func() { _ = hookLock.Close() }()
	if err := t.refresh(); err != nil {
		return err
	}
	if t.j.Phase != Committed && t.j.Phase != HooksRunning && t.j.Phase != HooksFailed {
		return ErrUnsafe
	}
	for t.j.Hooks.Next < len(t.j.Hooks.Plan) {
		i := t.j.Hooks.Next
		entry := t.j.Hooks.Plan[i]
		if entry.Kind != "shell" || entry.Command == "" || entry.Digest != hookDigest(entry) {
			return ErrUnsafe
		}
		t.j.Phase = HooksRunning
		if err := t.save(); err != nil {
			return err
		}
		if err := t.inject(fmt.Sprintf("hooks.before_run.%d", i)); err != nil {
			return err
		}
		if err := t.save(); err != nil {
			return err
		}
		err := exec(ctx, entry)
		if err := t.inject(fmt.Sprintf("hooks.after_run.%d", i)); err != nil {
			return err
		}
		if err != nil {
			if entry.Optional {
				t.j.Hooks.Failures = append(t.j.Hooks.Failures, fmt.Sprintf("%d:%s", i, err))
				t.j.Hooks.Next++
				if saveErr := t.save(); saveErr != nil {
					return saveErr
				}
				continue
			}
			// Hook failure does not roll back the committed target/registry
			// boundary. Keep the durable phase committed so recovery can retry.
			t.j.Phase = Committed
			if saveErr := t.save(); saveErr != nil {
				return saveErr
			}
			return err
		}
		t.j.Hooks.Next++
		if err := t.inject(fmt.Sprintf("hooks.before_checkpoint.%d", i)); err != nil {
			return err
		}
		if err := t.save(); err != nil {
			return err
		}
	}
	t.j.Phase = Committed
	if err := t.save(); err != nil {
		return err
	}
	return nil
}

func List(home string) ([]Journal, error) {
	root := filepath.Join(home, "transactions", "new")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Journal
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) < 4 || e.Name()[:3] != "tx-" {
			continue
		}
		tx, err := Load(home, e.Name()[3:])
		if err != nil {
			return nil, err
		}
		out = append(out, tx.j)
	}
	return out, nil
}

// Inventory statuses. Only StatusComplete and StatusAborted records are GC
// candidates; every other status is preserved evidence.
const (
	StatusActive     = "active"
	StatusComplete   = string(Complete)
	StatusAborted    = string(Aborted)
	StatusFuture     = "future"
	StatusMissingCAS = "missing-cas"
	StatusUnsafe     = "unsafe"
	// StatusOrphan is a transaction directory without a journal: a process
	// stopped before its first journal write, while the target was untouched.
	StatusOrphan = "orphan"
)

// statusForLoadError maps a Load refusal to its inventory status.
func statusForLoadError(err error) string { return inspect.StatusForLoadError(err) }

// TransactionStatus is a conservative inventory record. Unknown or damaged
// journals are retained and reported; inventory never turns evidence into a
// deletion candidate.
type TransactionStatus = inspect.TransactionStatus

func Inventory(home string) ([]TransactionStatus, error) { return inspect.Inventory(home) }

type GCPlan struct {
	IDs    []string
	DryRun bool
}

// Retention bounds for terminal global journals: a terminal record is kept
// while it is among the newest GCKeepNewest records and younger than
// GCRetention.
const (
	GCRetention  = 30 * 24 * time.Hour
	GCKeepNewest = 100
)

// PlanGC chooses only terminal, valid journals (complete or aborted) beyond
// the retention bounds, plus journal-less orphan directories older than
// GCRetention. Active, future, missing-CAS and unsafe records are never
// selected: they are recovery evidence.
func PlanGC(home string, now time.Time, dryRun bool) (GCPlan, error) {
	items, err := Inventory(home)
	if err != nil {
		return GCPlan{}, err
	}
	return GCPlan{IDs: selectGC(items, now), DryRun: dryRun}, nil
}

// selectGC is the pure retention rule behind PlanGC.
func selectGC(items []TransactionStatus, now time.Time) []string {
	type candidate struct {
		id string
		at time.Time
	}
	cutoff := now.Add(-GCRetention)
	var terminal []candidate
	ids := []string{}
	for _, item := range items {
		switch item.Status {
		case StatusComplete, StatusAborted:
			terminal = append(terminal, candidate{item.ID, item.UpdatedAt})
		case StatusOrphan:
			// An orphan has no journal and therefore no recovery authority,
			// but a young one may be a Begin in progress: only age selects it.
			if item.UpdatedAt.Before(cutoff) {
				ids = append(ids, item.ID)
			}
		}
	}
	sort.Slice(terminal, func(i, j int) bool {
		if terminal[i].at.Equal(terminal[j].at) {
			return terminal[i].id < terminal[j].id
		}
		return terminal[i].at.After(terminal[j].at)
	})
	for i, item := range terminal {
		if i >= GCKeepNewest || item.at.Before(cutoff) {
			ids = append(ids, item.id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ExecuteGC removes the planned journals while holding the global new lock,
// so no Begin, Continue or Abort can run concurrently. Every ID is
// re-inventoried under the lock and removed only if it is still eligible;
// a record that changed since planning is left in place.
func ExecuteGC(home string, plan GCPlan) error {
	if plan.DryRun || len(plan.IDs) == 0 {
		return nil
	}
	for _, id := range plan.IDs {
		if !validID(id) {
			return ErrUnsafe
		}
	}
	home, err := absClean(home)
	if err != nil {
		return err
	}
	holder, err := newID()
	if err != nil {
		return err
	}
	lock, err := acquireNewLock(filepath.Join(home, filepath.FromSlash(ledgerpath.NewLock)), holder)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	items, err := Inventory(home)
	if err != nil {
		return err
	}
	eligible := map[string]bool{}
	for _, id := range selectGC(items, time.Now().UTC()) {
		eligible[id] = true
	}
	for _, id := range plan.IDs {
		if !eligible[id] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(home, filepath.FromSlash(ledgerpath.NewTransactionsDir), "tx-"+id)); err != nil {
			return err
		}
	}
	return nil
}

// Continue completes a publishing transaction after a process crash. The
// caller supplies only the trusted registry home; the after image is read from
// the journal's immutable CAS, never rebuilt from mutable project input.
func Continue(home, id, registryHome string) error {
	return continueTx(home, id, registryHome, nil)
}

// continueTx is Continue with a crash-injection seam for recovery tests.
func continueTx(home, id, registryHome string, fault FaultInjector) error {
	return continueAdmittedTx(context.Background(), home, id, registryHome, fault, nil)
}

func continueAdmittedTx(ctx context.Context, home, id, registryHome string, fault FaultInjector, runtime *trustload.Runtime) error {
	home, err := absClean(home)
	if err != nil {
		return err
	}
	lock, err := acquireNewLock(filepath.Join(home, "transactions", "new.lock"), id)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	t, err := Load(home, id)
	if err != nil {
		return err
	}
	t.fault = fault
	t.managedRuntime = runtime
	if runtime != nil && t.managedReference == nil {
		return ErrManagedAdmission
	}
	if err := t.checkManaged(ctx, t.j.Phase == Prepared || t.j.Phase == Publishing, nil); err != nil {
		return err
	}
	registryHome, err = absClean(registryHome)
	if err != nil || registryHome == "" || t.j.RegistryTarget != state.ProjectsPath(registryHome) {
		return ErrUnsafe
	}
	if t.j.Phase == Committed || t.j.Phase == HooksRunning || t.j.Phase == HooksFailed {
		if t.sealedTree != "" {
			if err := t.verifySealedTree(t.j.Target); err != nil {
				return err
			}
		}
		// The commit record is durable; only the marker removal and the hook
		// suffix may remain. Both are idempotent.
		if err := t.removePending(); err != nil {
			return err
		}
		if t.j.Hooks.Next < len(t.j.Hooks.Plan) {
			return nil
		}
		return t.complete()
	}
	if t.j.Phase != Publishing && t.j.Phase != Prepared {
		return ErrUnsafe
	}
	if t.sealedTree != "" && !t.sealedReady {
		return ErrOwnershipUncertain
	}
	plan := RegistryPlan{Home: registryHome}
	if t.j.RegistryAfterSHA != "" {
		plan.After, err = t.readBlob(t.j.RegistryAfterSHA)
		if err != nil || digest(plan.After) != t.j.RegistryAfterSHA {
			return ErrUnsafe
		}
	}
	if t.j.Phase == Prepared {
		// A prepared journal is still abortable. Refuse before anything moves
		// unless it is complete and the staged tree is exactly the journaled
		// after image, so a doomed publish leaves the journal abortable.
		if t.j.TargetAfterSHA == "" || t.j.RegistryAfterSHA == "" {
			return ErrUnsafe
		}
		if _, statErr := os.Lstat(t.j.Target); statErr == nil {
			if err := t.verifyPending(); err != nil {
				return err
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		// Re-deriving the recovery manifest from the tree on disk must land
		// on the journaled address; otherwise the tree drifted after the
		// journal was written, and publishing it would bypass the after image.
		journaled := t.j.TargetAfterSHA
		if err := t.updateRecoveryManifest(); err != nil {
			t.j.TargetAfterSHA = journaled
			return err
		}
		if t.j.TargetAfterSHA != journaled {
			t.j.TargetAfterSHA = journaled
			return fmt.Errorf("%w: tree differs from the journaled after image", ErrUnsafe)
		}
		// As in Commit, the journal leaves Prepared before the target can
		// move: from here on abort must refuse, because the rendered tree may
		// already be published and only Continue can finish it.
		t.j.Phase = Publishing
		if err := t.save(); err != nil {
			return err
		}
		if t.j.TargetAfterSHA != journaled {
			// The tree changed between the check and the save. Nothing has
			// moved yet; the Publishing journal stays for inspection.
			return fmt.Errorf("%w: tree changed while publishing", ErrUnsafe)
		}
	}
	if _, statErr := os.Lstat(t.j.Target); os.IsNotExist(statErr) {
		if t.sealedTree != "" {
			if err := t.verifySealedTree(t.j.Staging); err != nil {
				return err
			}
		}
		if err := os.Rename(t.j.Staging, t.j.Target); err != nil {
			return err
		}
		if err := t.inject("continue.after_staging_publish"); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	} else {
		if err := t.verifyPending(); err != nil {
			return err
		}
	}
	// The published tree must be exactly the journaled after image before the
	// registry points at it.
	if err := t.verifyTargetAfter(); err != nil {
		return err
	}
	if len(plan.After) > 0 {
		if err := state.WithLock(registryHome, func() error {
			current, exists, _, err := state.ReadProjectsRaw(registryHome)
			if err != nil {
				return err
			}
			if !exists {
				current = nil
			}
			currentDigest := digest(current)
			if currentDigest == t.j.RegistryAfterSHA {
				return nil
			}
			if currentDigest != t.j.RegistryBeforeSHA {
				return ErrUnsafe
			}
			return state.WriteProjectsRaw(registryHome, plan.After, 0o600)
		}); err != nil {
			return err
		}
	}
	t.j.Phase = Committed
	record := commitRecordDigest(t.j.TargetAfterSHA, t.j.RegistryAfterSHA)
	t.j.CommitRecordSHA256 = &record
	if err := t.save(); err != nil {
		return err
	}
	if err := t.removePending(); err != nil {
		return err
	}
	if len(t.j.Hooks.Plan) > 0 {
		return nil
	}
	return t.complete()
}

// ContinueWithHooks resumes the global transaction and then executes its
// journalled hook suffix. It is the recovery primitive used by the CLI.
func ContinueWithHooks(ctx context.Context, home, id, registryHome string, exec HookExecutor) error {
	// Continue first: it publishes a pre-commit journal, and for a committed
	// one it removes a pending marker left by a crash before hooks ran.
	if err := Continue(home, id, registryHome); err != nil {
		return err
	}
	t, err := Load(home, id)
	if errors.Is(err, ErrNoActive) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := t.RunHooks(ctx, exec); err != nil {
		return err
	}
	return t.Finalize()
}

// AbortByID restores a staged target after a pre-commit crash. Registry
// mutation is intentionally not guessed here; it is only published after the
// target rename and remains CAS-guarded by Continue.
func AbortByID(home, id string) error {
	home, err := absClean(home)
	if err != nil {
		return err
	}
	lock, err := acquireNewLock(filepath.Join(home, "transactions", "new.lock"), id)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	t, err := Load(home, id)
	if err != nil {
		return err
	}
	return t.abortLocked()
}

func (t *Transaction) saveCAS(before, after []byte) error {
	blobs := filepath.Join(t.dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		return err
	}
	for _, b := range [][]byte{before, after} {
		path := filepath.Join(blobs, casLeaf(digest(b)))
		if existing, err := readCASFile(path); err == nil {
			if digest(existing) != digest(b) {
				return ErrUnsafe
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := writeFileDurable(path, b); err != nil {
			return err
		}
	}
	return t.save()
}

func (t *Transaction) saveCASBlob(ref string, data []byte) error {
	if !validDigest(ref) || digest(data) != ref {
		return ErrUnsafe
	}
	blobs := filepath.Join(t.dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		return err
	}
	path := filepath.Join(blobs, casLeaf(ref))
	if existing, err := readCASFile(path); err == nil {
		if string(existing) != string(data) {
			return ErrUnsafe
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeFileDurable(path, data)
}

func (t *Transaction) save() error {
	t.j.UpdatedAt = time.Now().UTC()
	// The manifest is immutable recovery input. Before the commit boundary it
	// is re-addressed whenever the journal changes, so active.json and all
	// executable metadata are bound by one CAS reference. From the commit
	// record on it is frozen: the record binds its address, and hooks may
	// legitimately change the published tree afterwards.
	if t.j.Phase == Prepared || t.j.Phase == Publishing || t.j.TargetAfterSHA == "" {
		if err := t.updateRecoveryManifest(); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(t.j, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurable(filepath.Join(t.dir, "active.json"), data)
}

// updateRecoveryManifest snapshots the immutable recovery inputs and stores
// them under their content address. The active journal is written only after
// this succeeds, so a journal can never reference a missing or partial CAS.
func (t *Transaction) updateRecoveryManifest() error {
	if t == nil || t.j.Target == "" || t.j.Staging == "" {
		return ErrUnsafe
	}
	root := t.j.Staging
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		root = t.j.Target
	}
	treeDigest := t.sealedTree
	if treeDigest == "" {
		tree, err := snapshotTree(root)
		if err != nil {
			return err
		}
		treeDigest = digest(tree)
	} else if t.sealedReady {
		if err := t.verifySealedTree(root); err != nil {
			return err
		}
	}
	manifest := recoveryManifest{
		Schema: Schema, Target: t.j.Target, PathDigest: digest([]byte(t.j.Target)),
		Staging: t.j.Staging, PendingMarker: t.j.PendingMarker,
		RegistryTarget: t.j.RegistryTarget,
		CreatedAt:      t.j.CreatedAt, TreeSHA256: treeDigest, BeforeTreeSHA: t.j.TargetBeforeTreeSHA,
		HookPlan:   append([]HookEntry(nil), t.j.Hooks.Plan...),
		SealedTree: t.sealedTree, SealedReady: t.sealedReady, ManagedPublication: t.managedReference,
	}
	if t.managedReference != nil {
		manifest.Schema = 2
		if t.managedReference.APIVersion == "tplaiter.dev/managed-publication-reference/v2" {
			manifest.Schema = 3
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	ref := digest(data)
	path := filepath.Join(t.dir, "blobs", "sha256", casLeaf(ref))
	if existing, readErr := readCASFile(path); readErr == nil {
		if digest(existing) != ref || string(existing) != string(data) {
			return ErrUnsafe
		}
	} else if os.IsNotExist(readErr) {
		if err := writeFileDurable(path, data); err != nil {
			return err
		}
	} else {
		return readErr
	}
	t.j.TargetAfterSHA = ref
	return nil
}

func loadRecoveryManifest(dir, ref string) (recoveryManifest, error) {
	return inspect.LoadManifest(dir, ref)
}

func (t *Transaction) inject(point string) error {
	if t == nil || t.fault == nil {
		return nil
	}
	return t.fault(point)
}

func digest(b []byte) string          { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func casLeaf(reference string) string { return strings.TrimPrefix(reference, "sha256:") }
func commitRecordDigest(target, registry string) string {
	return digest([]byte(commitDomain + "\x00" + target + "\x00" + registry))
}

func snapshotTree(root string) ([]byte, error) { return inspect.SnapshotTree(root) }

func (t *Transaction) verifyTargetAfter() error {
	if t == nil || t.j.TargetAfterSHA == "" {
		return ErrUnsafe
	}
	manifest, err := loadRecoveryManifest(t.dir, t.j.TargetAfterSHA)
	if err != nil {
		return err
	}
	snapshot, err := snapshotTree(t.j.Target)
	if err != nil || digest(snapshot) != manifest.TreeSHA256 {
		return ErrUnsafe
	}
	return nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func acquire(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f, false); err != nil {
		_ = f.Close()
		if errors.Is(err, errWouldBlock) {
			return nil, ErrActive
		}
		return nil, err
	}
	return f, nil
}

type newLockMetadata struct {
	APIVersion    string    `json:"apiVersion"`
	Holder        string    `json:"holder"`
	TransactionID string    `json:"transactionID"`
	PID           int       `json:"pid"`
	AcquiredAt    time.Time `json:"acquiredAt"`
}

// acquireNewLock treats the flock as authority and holder JSON as audit
// metadata only. It never deletes a stale-looking lock file.
func acquireNewLock(path, transactionID string) (*os.File, error) {
	if !validID(transactionID) {
		return nil, ErrUnsafe
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, ErrUnsafe
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if data, readErr := os.ReadFile(path); readErr == nil && len(strings.TrimSpace(string(data))) > 0 {
		var prior newLockMetadata
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if dec.Decode(&prior) != nil || prior.APIVersion != LockAPIVersion || prior.Holder == "" || !validID(prior.TransactionID) || prior.PID < 1 || prior.AcquiredAt.IsZero() {
			return nil, ErrUnsafe
		}
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	f, err := acquire(path)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(newLockMetadata{APIVersion: LockAPIVersion, Holder: "tplaiter", TransactionID: transactionID, PID: os.Getpid(), AcquiredAt: time.Now().UTC()})
	if err == nil {
		if err = f.Truncate(0); err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
		if err == nil {
			_, err = f.Write(metadata)
		}
		if err == nil {
			err = f.Sync()
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (t *Transaction) acquireGlobalLock() error {
	if t.lock != nil {
		return nil
	}
	lock, err := acquireNewLock(filepath.Join(t.home, "transactions", "new.lock"), t.j.ID)
	if err != nil {
		return err
	}
	t.lock = lock
	return nil
}

func (t *Transaction) refresh() error {
	current, err := Load(t.home, t.j.ID)
	if err != nil {
		return err
	}
	t.j = current.j
	t.sealedTree, t.sealedReady = current.sealedTree, current.sealedReady
	t.managedReference = current.managedReference
	return nil
}

func acquireExisting(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f, true); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (t *Transaction) releaseGlobalLock() {
	if t != nil && t.lock != nil {
		_ = t.lock.Close()
		t.lock = nil
	}
}

func (t *Transaction) verifyPending() error {
	return t.verifyPendingAt(t.j.Target)
}

func (t *Transaction) verifyPendingAt(root string) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafe
	}
	pendingDir, err := transactionDir(root, false)
	if err != nil {
		return err
	}
	path := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafe
	}
	var marker struct {
		TransactionID string `json:"transactionID"`
		Phase         string `json:"phase"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&marker); err != nil || dec.Decode(&struct{}{}) != io.EOF || marker.TransactionID != t.j.ID || marker.Phase != "pending" {
		return ErrUnsafe
	}
	return nil
}

func (t *Transaction) removePending() error {
	pendingDir, err := transactionDir(t.j.Target, false)
	if err != nil {
		return err
	}
	path := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return ErrUnsafe
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (t *Transaction) removePendingFromStaging() error {
	// A crash between staging and marker creation leaves no state directory
	// or no marker; both are valid pre-commit states.
	if _, err := os.Lstat(filepath.Join(t.j.Staging, naming.ProjectDir)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	pendingDir, err := transactionDir(t.j.Staging, false)
	if err != nil {
		return err
	}
	path := filepath.Join(pendingDir, filepath.Base(t.j.PendingMarker))
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return ErrUnsafe
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDirectory(pendingDir)
}

func (t *Transaction) complete() error {
	if t.sealedTree != "" {
		if err := t.verifySealedTree(t.j.Target); err != nil {
			return err
		}
	}
	t.j.Phase = Complete
	if err := t.save(); err != nil {
		return err
	}
	return os.RemoveAll(t.dir)
}

func (t *Transaction) readBlob(name string) ([]byte, error) {
	if !validDigest(name) {
		return nil, ErrUnsafe
	}
	path := filepath.Join(t.dir, "blobs", "sha256", casLeaf(name))
	data, err := readCASFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMissingCAS
	}
	if err != nil || digest(data) != name {
		return nil, ErrUnsafe
	}
	return data, nil
}

func readCASFile(path string) ([]byte, error) { return inspect.ReadCASFile(path) }

func validateJournal(home, dir, id string, j Journal) error {
	return inspect.ValidateJournal(home, dir, id, j)
}

func hookDigest(h HookEntry) string { return digest([]byte(h.Kind + "\x00" + h.Command)) }
func validID(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func validDigest(v string) bool {
	if !strings.HasPrefix(v, "sha256:") || len(v) != len("sha256:")+64 {
		return false
	}
	hexValue := strings.TrimPrefix(v, "sha256:")
	if strings.ToLower(hexValue) != hexValue {
		return false
	}
	_, err := hex.DecodeString(hexValue)
	return err == nil
}

func absClean(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil
}

// rejectSymlinkStateDir refuses a target whose state directory is a symlink or
// a non-directory: the pending marker must never be written through it.
func rejectSymlinkStateDir(root string) error {
	info, err := os.Lstat(filepath.Join(root, naming.ProjectDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: state directory is not a real directory", ErrUnsafe)
	}
	return nil
}

func rejectSymlinkParents(path string) error {
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink parent", ErrUnsafe)
	}
	return nil
}

func writeFileDurable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// transactionDir is deliberately lstat-based: a rendered template must never
// turn the transaction marker into a write through a symlinked state directory.
func transactionDir(root string, create bool) (string, error) {
	dir := filepath.Join(root, naming.ProjectDir)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", ErrUnsafe
	}
	return dir, nil
}

// peekAPIVersion returns the top-level apiVersion string, or "" when data is
// not a JSON object carrying one.
func peekAPIVersion(data []byte) string {
	var head struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return ""
	}
	return head.APIVersion
}

// Release drops the process-held global lock without touching the journal,
// as a process exit would. The transaction then stays recoverable by
// Continue or AbortByID from any process. It is idempotent.
func (t *Transaction) Release() { t.releaseGlobalLock() }
