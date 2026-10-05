package stateledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

// NewDependencyLock builds the sealed dependency lock for root. A nil
// dependency list becomes the explicit empty array: the "no dependencies"
// state is always written as `"dependencies": []`, never omitted or null.
func NewDependencyLock(root provenance.RootTemplateLock, dependencies []provenance.DependencySubject) (provenance.TemplateLock, error) {
	if err := root.Validate(); err != nil {
		return provenance.TemplateLock{}, fmt.Errorf("%w: root lock: %w", ErrUnsafe, err)
	}
	if dependencies == nil {
		dependencies = []provenance.DependencySubject{}
	}
	lock := provenance.TemplateLock{
		APIVersion:     provenance.TemplateLockAPIVersion,
		Kind:           provenance.DependencyExportLockKind,
		TrustProfile:   root.TrustProfile,
		RootLockSHA256: root.RootLockSHA256,
		Dependencies:   append([]provenance.DependencySubject{}, dependencies...),
	}
	digest, err := provenance.ComputeTemplateLockSHA256(lock)
	if err != nil {
		return provenance.TemplateLock{}, err
	}
	lock.LockSHA256 = digest
	if err := provenance.ValidateLockPair(root, lock); err != nil {
		return provenance.TemplateLock{}, fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	return lock, nil
}

// SealRootLock fills RootLockSHA256 and validates the result.
func SealRootLock(lock provenance.RootTemplateLock) (provenance.RootTemplateLock, error) {
	lock.RootLockSHA256 = ""
	digest, err := provenance.ComputeRootLockSHA256(lock)
	if err != nil {
		return provenance.RootTemplateLock{}, err
	}
	lock.RootLockSHA256 = digest
	if err := lock.Validate(); err != nil {
		return provenance.RootTemplateLock{}, fmt.Errorf("%w: root lock: %w", ErrUnsafe, err)
	}
	return lock, nil
}

// WriteLockPair durably writes a validated root and dependency lock pair as
// canonical JSON. The dependency lock is written first: a crash between the
// two writes leaves an old root lock that no longer matches, which every
// reader refuses, rather than a new root lock silently paired with stale
// dependencies. It returns the exact bytes written.
func WriteLockPair(projectRoot string, root provenance.RootTemplateLock, dependencies provenance.TemplateLock) (rootJSON, dependencyJSON []byte, err error) {
	if dependencies.Dependencies == nil {
		return nil, nil, fmt.Errorf("%w: dependency lock must carry an explicit dependencies array", ErrUnsafe)
	}
	if err := provenance.ValidateLockPair(root, dependencies); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrUnsafe, err)
	}
	projectRoot, _, err = validateRoots(projectRoot, "")
	if err != nil {
		return nil, nil, err
	}
	if rootJSON, err = canonicaljson.Canonical(root); err != nil {
		return nil, nil, err
	}
	if dependencyJSON, err = canonicaljson.Canonical(dependencies); err != nil {
		return nil, nil, err
	}
	if err = writeLedger(projectRoot, DependencyLockFile, dependencyJSON); err != nil {
		return nil, nil, err
	}
	if err = writeLedger(projectRoot, RootLockFile, rootJSON); err != nil {
		return nil, nil, err
	}
	return rootJSON, dependencyJSON, nil
}

// ApplyPlan re-plans the migration, requires the fresh plan to match the
// reviewed expectedPlanSHA256 exactly, and then durably writes its images:
// the synthesized dependency lock first and the project marker last, so the
// marker switch to project/v2 is the commit point. A plan without mutations
// is a no-op. It returns the plan it applied.
func ApplyPlan(projectRoot string, opts Options, expectedPlanSHA256 string) (*MigrationPlan, error) {
	return ApplyPlanContext(context.Background(), projectRoot, opts, expectedPlanSHA256)
}

// ApplyPlanContext propagates cancellation to planning and checks it immediately
// before the marker commit point. Writer coordination belongs to the concrete
// runtime assembly; this compatibility writer does not grant native admission.
func ApplyPlanContext(ctx context.Context, projectRoot string, opts Options, expectedPlanSHA256 string, retained ...*BoundMigrationWriter) (*MigrationPlan, error) {
	if len(retained) > 1 || len(retained) == 1 && (retained[0] == nil || retained[0].rootPath != projectRoot) {
		return nil, ErrUnsafe
	}
	plan, err := PlanContext(ctx, projectRoot, opts)
	if err != nil {
		return nil, err
	}
	if plan.PlanSHA256 != expectedPlanSHA256 {
		return nil, fmt.Errorf("%w: plan changed since review (have %s, want %s)", ErrDigest, plan.PlanSHA256, expectedPlanSHA256)
	}
	// The final internal planner may invoke readers/context callbacks. Recheck
	// retained root/state/home/lock bindings AFTER it, before any mutation.
	if len(retained) == 1 {
		if err := retained[0].Check(ctx); err != nil {
			return nil, err
		}
	}
	if len(plan.Mutations) == 0 {
		return plan, nil
	}
	root, _, err := validateRoots(projectRoot, "")
	if err != nil {
		return nil, err
	}
	write := func(name string, data []byte) error {
		if len(retained) == 1 {
			return retained[0].write(ctx, name, data)
		}
		return writeLedger(root, name, data)
	}
	if len(plan.DependencyLockJSON) > 0 {
		if err := write(DependencyLockFile, plan.DependencyLockJSON); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := write("project.yaml", plan.ProjectYAML); err != nil {
		return nil, err
	}
	return plan, nil
}

// writeFailpoint is a deterministic crash-injection seam for tests. It is nil
// in production.
var writeFailpoint func(stage, name string) error

func failpoint(stage, name string) error {
	if writeFailpoint == nil {
		return nil
	}
	return writeFailpoint(stage, name)
}

// writeLedger atomically and durably replaces StateDir/name. The state
// directory and the final path must not be symlinks; the temporary file is
// fsynced before the rename and the directory after it.
func writeLedger(projectRoot, name string, data []byte) error {
	dir := filepath.Join(projectRoot, StateDir)
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		if err := syncDir(projectRoot); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory", ErrUnsafe, StateDir)
	}
	target := filepath.Join(dir, name)
	if existing, err := os.Lstat(target); err == nil && (existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular()) {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, name)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
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
	if err := failpoint("before-rename", name); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	if err := failpoint("before-dir-sync", name); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	written, err := stableRead(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(written, data) {
		return fmt.Errorf("%w: %s changed during write", ErrUnsafe, name)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
