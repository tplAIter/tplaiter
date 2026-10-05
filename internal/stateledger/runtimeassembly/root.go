package runtimeassembly

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// concreteRoot cannot be constructed through Options. Context-aware ledger
// entry points pass the operation context to its installed runtime checks.
type concreteRoot struct {
	runtime *trustload.Runtime
}

func (v concreteRoot) VerifyRoot(ctx context.Context, root string) (stateledger.RootEvidence, error) {
	r := v.runtime
	if err := ctx.Err(); err != nil {
		return stateledger.RootEvidence{}, err
	}
	if r.TrustRuntime() == nil || root != r.ProjectContext().RootPath {
		return stateledger.RootEvidence{}, stateledger.ErrProjectIdentity
	}
	if err := stateledger.VerifyDependencyLocks(ctx, root, r.TrustRuntime(), r); err != nil {
		return stateledger.RootEvidence{}, err
	}
	raw, err := confinedLedger(root, stateledger.RootLockFile)
	if err != nil {
		return stateledger.RootEvidence{}, err
	}
	lock, err := provenance.DecodeRootTemplateLock(raw)
	if err != nil {
		return stateledger.RootEvidence{}, err
	}
	dependenciesRaw, err := confinedLedger(root, stateledger.DependencyLockFile)
	if err != nil {
		return stateledger.RootEvidence{}, err
	}
	dependencies, err := provenance.DecodeTemplateLock(dependenciesRaw)
	if err != nil {
		return stateledger.RootEvidence{}, err
	}
	if err := provenance.ValidateLockPair(*lock, *dependencies); err != nil {
		return stateledger.RootEvidence{}, err
	}
	for _, subject := range append([]provenance.DependencySubject{provenance.DependencySubject(lock.Root)}, dependencies.Dependencies...) {
		source := provenance.RootSubject(subject)
		stable := r.TrustRuntime()
		if stable == nil {
			return stateledger.RootEvidence{}, stateledger.ErrProjectIdentity
		}
		proof, err := stable.VerifySubject(ctx, source.Subject(), trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: source.StatementCAS, SignatureCAS: source.SignatureCAS, KeyFingerprint: source.KeyFingerprint, CheckpointCAS: source.CheckpointCAS, InclusionProofCAS: source.InclusionProofCAS})
		if err != nil {
			return stateledger.RootEvidence{}, err
		}
		if !proof.ValidFor(stable, stable.Binding()) {
			return stateledger.RootEvidence{}, stateledger.ErrPolicyOrigin
		}
	}
	return stateledger.RootEvidence{Origin: lock.Root.Origin, TemplatePath: lock.Root.TemplatePath, RequestedRef: lock.Root.RequestedRef, Commit: lock.Root.Commit, RootLockSHA256: lock.RootLockSHA256}, nil
}

func confinedLedger(root, leaf string) ([]byte, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer held.Close()
	state, err := held.Lstat(stateledger.StateDir)
	if err != nil {
		return nil, err
	}
	if !state.IsDir() {
		return nil, stateledger.ErrUnsafe
	}
	rel := filepath.Join(stateledger.StateDir, leaf)
	info, err := held.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, stateledger.ErrUnsafe
	}
	f, err := held.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, stateledger.ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("%w: ledger exceeds limit", stateledger.ErrUnsafe)
	}
	current, err := held.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, current) || current.Mode() != info.Mode() || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
		return nil, stateledger.ErrUnsafe
	}
	if current.Mode()&fs.ModeSymlink != 0 {
		return nil, stateledger.ErrUnsafe
	}
	return data, nil
}
