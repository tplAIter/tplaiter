package operationtrust

import (
	"context"
	"errors"
	"sort"

	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// AuthorizeActions admits only the exact request/material pairs already
// contained in operation. It never runs, stages, installs, or resolves tools.
func AuthorizeActions(ctx context.Context, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, operation trustverify.OperationInputs, requests []trustverify.ExecutionRequest, refs []trustverify.ApprovalRefs) ([]*trustverify.ExecutionPermit, error) {
	if ctx == nil || runtime == nil || resolution == nil || len(requests) == 0 || len(requests) != len(refs) || len(requests) != len(operation.Actions) {
		return nil, errors.New("TRUST_REQUEST_INVALID")
	}
	if _, err := trustverify.ComputeOperationInputsSHA256(operation); err != nil {
		return nil, errors.New("TRUST_REQUEST_INVALID")
	}
	permits := make([]*trustverify.ExecutionPermit, len(requests))
	for i := range requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		permit, err := runtime.Authorize(ctx, resolution, operation, requests[i], refs[i])
		if err != nil {
			return nil, err
		}
		if _, err := runtime.PersistentApprovalReference(permit); err != nil {
			return nil, errors.New("TRUST_APPROVAL_MISMATCH")
		}
		permits[i] = permit
	}
	return permits, nil
}

// RecheckAction is the final no-spawn gate. A lifecycle owner supplies frozen
// staged bytes immediately before execution; this package never invokes a
// runner or opens a project path.
func RecheckAction(ctx context.Context, runtime *trustverify.Runtime, permit *trustverify.ExecutionPermit, request trustverify.ExecutionRequest, staged trustverify.StagedMaterialReader) error {
	if ctx == nil || runtime == nil || permit == nil || staged == nil {
		return errors.New("TRUST_APPROVAL_MISMATCH")
	}
	return runtime.RecheckExecution(ctx, permit, request, staged)
}

// BuildActionfulUpdatePlan seals only an already prepared source/target pair
// with the exact persistent permits minted by AuthorizeActions. It has no
// execution or publication path; callers still must use RecheckAction at the
// lifecycle boundary.
func BuildActionfulUpdatePlan(runtime *trustverify.Runtime, prepared *PreparedUpdate, operation trustverify.OperationInputs, requests []trustverify.ExecutionRequest, permits []*trustverify.ExecutionPermit, createdAt string) (*provenance.UpdatePlan, error) {
	if runtime == nil || prepared == nil || !prepared.ValidFor(runtime) || len(operation.Actions) == 0 || len(operation.Actions) != len(requests) || len(requests) != len(permits) {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	previewOperation := operation
	previewOperation.Actions = []trustverify.ActionMaterial{}
	previewDigest, err := trustverify.ComputeOperationInputsSHA256(previewOperation)
	if err != nil || previewDigest != prepared.operation {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	digest, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil {
		return nil, errors.New("TRUST_REQUEST_INVALID")
	}
	actions := make([]provenance.PlanAction, len(requests))
	for i, request := range requests {
		a := operation.Actions[i]
		if request.OperationInputsSHA256 != digest || request.ProjectID != operation.ProjectID || request.Scope != "update" || request.VerifyRequestSHA256() != nil || !sameMaterial(request, a) {
			return nil, errors.New("TRUST_REQUEST_INVALID")
		}
		if _, err := runtime.PersistentApprovalReference(permits[i]); err != nil {
			return nil, errors.New("TRUST_APPROVAL_MISMATCH")
		}
		actions[i] = provenance.PlanAction{RequestSHA256: request.RequestSHA256, OperationInputsSHA256: digest, Provider: provenance.PlanProvider(a.Provider), Action: provenance.PlanActionDefinition(a.Action), Tool: provenance.PlanTool(a.Tool), WorkingDirectoryScope: provenance.PlanWorkingDirectory(a.WorkingDirectoryScope), EnvironmentPolicySHA256: a.EnvironmentPolicySHA256, TimeoutMillis: a.TimeoutMillis, Migration: provenance.PlanMigration(a.Migration)}
	}
	outputs := planOutputs(prepared.rendered)
	return provenance.BuildStableUpdatePlan(provenance.StablePlanInput{Runtime: runtime, Source: provenance.StablePlanLockInput{Resolution: prepared.sourceResolution, Root: prepared.source, Dependencies: prepared.sourceDeps}, Target: provenance.StablePlanLockInput{Resolution: prepared.targetResolution, Root: prepared.target, Dependencies: prepared.targetDeps}, OperationInputsSHA256: digest, Permits: permits, PreimageSHA256: operation.PreimageSHA256, Actions: actions, Outputs: outputs, CreatedAt: createdAt})
}

func sameMaterial(request trustverify.ExecutionRequest, material trustverify.ActionMaterial) bool {
	if request.Provider != material.Provider || request.Tool != material.Tool || request.WorkingDirectoryScope != material.WorkingDirectoryScope || request.EnvironmentPolicySHA256 != material.EnvironmentPolicySHA256 || request.TimeoutMillis != material.TimeoutMillis || request.Migration != material.Migration || request.Action.ID != material.Action.ID || request.Action.Kind != material.Action.Kind || request.Action.Phase != material.Action.Phase || request.Action.Shell != material.Action.Shell || request.Action.ContentClosureSHA256 != material.Action.ContentClosureSHA256 || len(request.Action.Argv) != len(material.Action.Argv) {
		return false
	}
	for i := range request.Action.Argv {
		if request.Action.Argv[i] != material.Action.Argv[i] {
			return false
		}
	}
	return true
}

func planOutputs(r *renderref.Result) []provenance.PlanOutput {
	if r == nil {
		return nil
	}
	keys := make([]string, 0, len(r.Files))
	for path := range r.Files {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	out := make([]provenance.PlanOutput, 0, len(keys))
	for _, path := range keys {
		out = append(out, provenance.PlanOutput{Path: path, ContentSHA256: rawDigest(r.Files[path])})
	}
	return out
}
