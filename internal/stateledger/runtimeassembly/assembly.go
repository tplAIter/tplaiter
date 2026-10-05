// Package runtimeassembly composes ledger readers and migration with an actual
// installed runtime. The low-level ledger compatibility APIs remain separate.
package runtimeassembly

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

var ErrJournal = errors.New("stateledger: native journal is not ready")

// JournalError preserves the precise observation without projecting an unsigned
// phase or converting unknown coverage into corruption.
type JournalError struct {
	ID     string
	Status inventory.Status
}

func (e *JournalError) Error() string { return fmt.Sprintf("%s: %s (%s)", ErrJournal, e.ID, e.Status) }
func (e *JournalError) Unwrap() error { return ErrJournal }

// Options supplies locators and a secret classifier, never authority material.
type Options struct {
	Home           string
	SecretProvider stateledger.SecretDigestProvider
}

// Observation contains historical authenticated receipts alongside the current
// ledger. It is not a write capability or a durable terminal confirmation.
type Observation struct {
	Snapshot *stateledger.Snapshot
	Journals []inventory.Record
}

func journals(ctx context.Context, r *trustload.Runtime, home string) ([]inventory.Record, error) {
	records, err := inventory.Read(ctx, r, home)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if !record.Sealed() || !record.Terminal() {
			return nil, &JournalError{record.ID(), record.Status()}
		}
		for _, issue := range record.Issues() {
			return nil, &JournalError{record.ID(), issue}
		}
	}
	return records, nil
}

// VerifyReadOnly uses the concrete runtime's held CAS, checks current marker
// identity through VerifyStable, and reobserves native receipts after ledger
// callbacks. Historical terminal images need not equal later current targets.
// No locks, keys, journals or caches are created by this read-only operation.
func VerifyReadOnly(ctx context.Context, r *trustload.Runtime, opts Options) (*Observation, error) {
	session, err := OpenReadOnly(ctx, r, opts)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	if err := session.Recheck(ctx); err != nil {
		return nil, err
	}
	return session.Observation(), nil
}

// verifyUnderCoordination is private: its callers already retain actual native
// reader or writer inodes and check them across the complete operation.
func verifyUnderCoordination(ctx context.Context, r *trustload.Runtime, opts Options) (*Observation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	before, err := journals(ctx, r, opts.Home)
	if err != nil {
		return nil, err
	}
	snapshot, err := stateledger.VerifyStable(ctx, r.ProjectContext().RootPath, r.TrustRuntime(), stateledger.StableVerifyOptions{HomeRoot: opts.Home, CAS: r, SecretProvider: opts.SecretProvider})
	if err != nil {
		return nil, err
	}
	after, err := journals(ctx, r, opts.Home)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before, after) {
		return nil, fmt.Errorf("%w: native receipt changed during observation", stateledger.ErrUnsafe)
	}
	return &Observation{snapshot, after}, nil
}

// Load is the same concrete read-only boundary; it never discovers or installs
// authority when the caller has no installed runtime.
func Load(ctx context.Context, r *trustload.Runtime, opts Options) (*Observation, error) {
	return VerifyReadOnly(ctx, r, opts)
}

// Plan verifies source signatures and the current observed marker through an
// installed runtime. Existing dependency locks are required; it does not infer
// dependency-free source or synthesize missing evidence.
func Plan(ctx context.Context, r *trustload.Runtime, opts Options) (*stateledger.MigrationPlan, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	held, err := holdReaders(ctx, r.ProjectContext().RootPath, opts.Home)
	if err != nil {
		return nil, err
	}
	defer held.close()
	plan, err := planUnderCoordination(ctx, r, opts)
	if err != nil {
		return nil, err
	}
	if err := held.check(ctx); err != nil {
		return nil, err
	}
	return plan, nil
}

func planUnderCoordination(ctx context.Context, r *trustload.Runtime, opts Options) (*stateledger.MigrationPlan, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	records, err := inventory.Read(ctx, r, opts.Home)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 {
		if _, err := verifyUnderCoordination(ctx, r, opts); err != nil {
			return nil, err
		}
	}
	plan, err := stateledger.PlanContext(ctx, r.ProjectContext().RootPath, stateledger.Options{HomeRoot: opts.Home, SecretProvider: opts.SecretProvider, RootVerifier: concreteRoot{r}})
	if err != nil {
		return nil, err
	}
	stable := r.TrustRuntime()
	if stable == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	if err := stable.CheckProjectIdentity(ctx, r.ProjectContext().RootPath, plan.ProjectID); err != nil {
		return nil, err
	}
	if _, err := (concreteRoot{r}).VerifyRoot(ctx, r.ProjectContext().RootPath); err != nil {
		return nil, err
	}
	if plan.From == stateledger.ProjectV2APIVersion {
		if _, err := verifyUnderCoordination(ctx, r, opts); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

// ApplyPlan keeps Root and Home unchanged. It re-plans under the actual native
// project/home writer locks and uses the existing marker-last migration writer.
// Authority relocation and absent dependency evidence are unsupported.
func ApplyPlan(ctx context.Context, r *trustload.Runtime, opts Options, digest string) (*stateledger.MigrationPlan, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	held, err := holdWriters(ctx, r.ProjectContext().RootPath, opts.Home)
	if err != nil {
		return nil, err
	}
	defer held.close()
	bound, err := held.bindMigrationWriter(ctx)
	if err != nil {
		return nil, err
	}
	defer bound.Close()
	if err := held.check(ctx); err != nil {
		return nil, err
	}
	plan, err := planUnderCoordination(ctx, r, opts)
	if err != nil {
		return nil, err
	}
	if plan.PlanSHA256 != digest {
		return nil, stateledger.ErrDigest
	}
	if err := held.check(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	applied, err := stateledger.ApplyPlanBoundContext(ctx, r.ProjectContext().RootPath, stateledger.Options{HomeRoot: opts.Home, SecretProvider: opts.SecretProvider, RootVerifier: concreteRoot{r}}, digest, bound)
	if err != nil {
		return nil, err
	}
	if err := held.check(ctx); err != nil {
		return nil, err
	}
	if _, err := verifyUnderCoordination(ctx, r, opts); err != nil {
		return nil, err
	}
	return applied, nil
}
