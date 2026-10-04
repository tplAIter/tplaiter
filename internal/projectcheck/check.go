// Package projectcheck provides the read-only project check projection.
package projectcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

type Options struct {
	ProjectRoot    string
	HomeRoot       string
	Authority      stateledger.BindingAuthority
	CAS            evidencecas.Reader
	SecretProvider stateledger.SecretDigestProvider
}

type Report struct {
	APIVersion string               `json:"apiVersion"`
	Status     string               `json:"status"`
	Managed    ManagedState         `json:"managed"`
	Findings   []string             `json:"findings"`
	Verify     projectverify.Report `json:"verify"`
}

type ManagedState struct {
	State    string   `json:"state"`
	Modified []string `json:"modified"`
	Missing  []string `json:"missing"`
	Invalid  []string `json:"invalid"`
}

// Run performs the same canonical verification as verify. It has no refresh,
// resolver, network, or writer option by construction.
func Run(ctx context.Context, opts Options) (Report, error) {
	report := Report{
		APIVersion: "tplaiter.dev/project-check/v1",
		Status:     "pass",
		Managed:    ManagedState{State: "not-applicable", Modified: []string{}, Missing: []string{}, Invalid: []string{}},
		Findings:   []string{},
	}
	verified, snapshot, err := projectverify.VerifyObserved(ctx, opts.ProjectRoot, opts.Authority, projectverify.Options{
		HomeRoot: opts.HomeRoot, CAS: opts.CAS, SecretProvider: opts.SecretProvider,
	})
	if err != nil {
		report.Status = "fail"
		report.Managed.State = "invalid"
		return report, err
	}
	report.Verify = verified
	managed, managedErr := checkManagedObserved(ctx, opts.ProjectRoot, snapshot)
	if managedErr != nil {
		report.Status = "fail"
		report.Managed = managed
		report.Findings = append(report.Findings, "invalid-ownership")
		return report, managedErr
	}
	report.Managed = managed
	if managed.State == "drift" || managed.State == "invalid" {
		report.Status = "fail"
		report.Findings = append(report.Findings, "managed-drift")
	}
	return report, nil
}

func checkManaged(root string) (ManagedState, error) {
	return checkManagedObserved(context.Background(), root, nil)
}

func ownershipError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return resultdto.NewDiagnosticError(resultdto.Diagnostic{Code: projectverify.CancelledCode, Severity: "error", Message: "project check cancelled"}, projectverify.ExitCancelled, cancellationCause(err))
	}
	return resultdto.NewDiagnosticError(resultdto.Diagnostic{Code: projectverify.StateCode, Severity: "error", Message: "ownership inventory is invalid"}, resultdto.ExitOperational, err)
}

func cancellationCause(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

func checkManagedObserved(ctx context.Context, root string, snapshot *stateledger.Snapshot) (ManagedState, error) {
	state := ManagedState{State: "not-applicable", Modified: []string{}, Missing: []string{}, Invalid: []string{}}
	observation, err := projectverify.OpenObservation(ctx, root)
	if err != nil {
		return state, ownershipError(err)
	}
	defer func() { _ = observation.Close() }()
	invalid := func(err error) (ManagedState, error) {
		state.State = "invalid"
		state.Invalid = append(state.Invalid, ownership.InventoryRelPath)
		return state, ownershipError(err)
	}
	image, err := observation.ReadState(ctx, ownership.InventoryRelPath)
	if err != nil {
		return invalid(err)
	}
	if !image.Exists {
		if snapshot != nil {
			for _, entry := range snapshot.Entries {
				if entry.Scope == "project" && entry.Path == ownership.InventoryRelPath && entry.Exists {
					return invalid(stateledger.ErrUnsafe)
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return invalid(err)
		}
		return state, nil
	}
	if image.Kind != ownership.KindFile {
		return invalid(stateledger.ErrUnsafe)
	}
	raw := image.Data
	if snapshot != nil {
		raw, err = observation.ReadVerified(ctx, snapshot, ownership.InventoryRelPath)
		if err != nil {
			return invalid(err)
		}
	}
	var inventory ownership.Inventory
	if err := canonicaljson.DecodeStrict(raw, &inventory); err != nil {
		return invalid(err)
	}
	if err := validateInventory(inventory); err != nil {
		return invalid(err)
	}
	state.State = "clean"
	for _, artifact := range inventory.Artifacts {
		actual, readErr := observation.ReadState(ctx, artifact.Path)
		if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
			return invalid(readErr)
		}
		if readErr != nil {
			state.Invalid = append(state.Invalid, artifact.Path)
			continue
		}
		if !actual.Exists {
			state.Missing = append(state.Missing, artifact.Path)
			continue
		}
		linkTarget := ""
		if actual.Kind == ownership.KindSymlink {
			linkTarget = string(actual.Data)
		}
		observed, artifactErr := ownership.ArtifactFor(artifact.Path, actual.Data, actual.Mode, linkTarget)
		if artifactErr != nil {
			state.Invalid = append(state.Invalid, artifact.Path)
			continue
		}
		if !sameArtifact(artifact, observed) {
			state.Modified = append(state.Modified, artifact.Path)
		}
	}
	sort.Strings(state.Modified)
	sort.Strings(state.Missing)
	sort.Strings(state.Invalid)
	if len(state.Modified)+len(state.Missing)+len(state.Invalid) > 0 {
		state.State = "drift"
	}
	if snapshot != nil {
		current, err := observation.ReadVerified(ctx, snapshot, ownership.InventoryRelPath)
		if err != nil {
			return invalid(err)
		}
		if string(current) != string(raw) {
			return invalid(stateledger.ErrUnsafe)
		}
	}
	if err := ctx.Err(); err != nil {
		return invalid(err)
	}
	return state, nil
}

func sameArtifact(expected, observed ownership.Artifact) bool {
	if expected.SHA256 != observed.SHA256 {
		return false
	}
	if expected.Kind == ownership.KindSymlink || observed.Kind == ownership.KindSymlink {
		return expected.Kind == ownership.KindSymlink && observed.Kind == ownership.KindSymlink && expected.Target == observed.Target
	}
	return (expected.Kind == "" || expected.Kind == ownership.KindFile) && expected.Mode != 0 && expected.Mode == observed.Mode
}

// RunResult adapts the safe typed diagnostics to the shared result/v1 DTO.
func RunResult(ctx context.Context, opts Options, version string) (resultdto.Result, int, error) {
	report, runErr := Run(ctx, opts)
	r := resultdto.New(resultdto.OperationProjectCheck, version)
	r.Project = &resultdto.Project{ID: report.Verify.ProjectID, Root: opts.ProjectRoot}
	if runErr != nil {
		r.Status = resultdto.StatusForExit(resultdto.Classify(runErr))
		r.Diagnostics = resultdto.ProjectDiagnostics(runErr)
		return r.Canonical(), resultdto.Classify(runErr).Int(), runErr
	}
	if report.Managed.State == "invalid" {
		err := ownershipError(stateledger.ErrUnsafe)
		r.Status = resultdto.StatusForExit(resultdto.Classify(err))
		r.Diagnostics = resultdto.ProjectDiagnostics(err)
		return r.Canonical(), resultdto.Classify(err).Int(), err
	}
	if report.Managed.State == "drift" {
		r.Status = resultdto.StatusChanges
	}
	return r.Canonical(), int(resultdto.ExitSuccess), nil
}

// The owner ArtifactFor and ValidateRelativeSymlink enforce the canonical
// path namespace. Metadata, duplicate and collision checks mirror Inventory v1.
func validateInventory(inventory ownership.Inventory) error {
	if inventory.Version != 1 {
		return stateledger.ErrUnsafe
	}
	paths := map[string]bool{}
	validatePath := func(rel string) error { _, err := ownership.ArtifactFor(rel, nil, 0, ""); return err }
	for _, artifact := range inventory.Artifacts {
		if err := validatePath(artifact.Path); err != nil {
			return err
		}
		raw, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(raw) != sha256.Size {
			return stateledger.ErrUnsafe
		}
		switch artifact.Kind {
		case "", ownership.KindFile:
			if artifact.Mode > 0o777 || artifact.Target != "" {
				return stateledger.ErrUnsafe
			}
		case ownership.KindSymlink:
			if artifact.Mode != 0 {
				return stateledger.ErrUnsafe
			}
			if err := ownership.ValidateRelativeSymlink(artifact.Path, artifact.Target); err != nil {
				return err
			}
			sum := sha256.Sum256([]byte(artifact.Target))
			if artifact.SHA256 != hex.EncodeToString(sum[:]) {
				return stateledger.ErrUnsafe
			}
		default:
			return stateledger.ErrUnsafe
		}
		if paths[artifact.Path] {
			return fmt.Errorf("%w: duplicate artifact", stateledger.ErrUnsafe)
		}
		paths[artifact.Path] = true
	}
	tombstones := map[string]bool{}
	for _, rel := range inventory.Tombstones {
		if err := validatePath(rel); err != nil {
			return err
		}
		if paths[rel] || tombstones[rel] {
			return stateledger.ErrUnsafe
		}
		tombstones[rel] = true
	}
	skipped := map[string]bool{}
	for _, entry := range inventory.Skipped {
		if err := validatePath(entry.Path); err != nil {
			return err
		}
		if entry.Reason == "" || skipped[entry.Path] {
			return stateledger.ErrUnsafe
		}
		skipped[entry.Path] = true
	}
	return nil
}
