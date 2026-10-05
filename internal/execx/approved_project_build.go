package execx

import (
	"context"
	"errors"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type ProjectProcessResult struct {
	BuildVariant         string `json:"buildVariant,omitempty"`
	BuildVariantSHA256   string `json:"buildVariantSHA256,omitempty"`
	ModuleIndexSHA256    string `json:"moduleIndexSHA256,omitempty"`
	RequestSHA256        string `json:"requestSHA256"`
	InputClosureSHA256   string `json:"inputClosureSHA256"`
	ToolchainIndexSHA256 string `json:"toolchainIndexSHA256"`
	ExitCode             int    `json:"exitCode"`
	TimedOut             bool   `json:"timedOut"`
	Cancelled            bool   `json:"cancelled"`
	Stdout               string `json:"stdout"`
	Stderr               string `json:"stderr"`
	StdoutSHA256         string `json:"stdoutSHA256"`
	StderrSHA256         string `json:"stderrSHA256"`
}
type ProcessReceipt struct {
	runner  *ApprovedRunner
	request string
	result  ProjectProcessResult
}

func (r *ApprovedRunner) ExecuteProjectBuild(ctx context.Context, permit *trustverify.ExecutionPermit, request trustverify.ExecutionRequest, material *operationtrust.ExecutionMaterial) (*ProcessReceipt, error) {
	if ctx == nil || r == nil || r.runtime == nil || permit == nil || material == nil {
		return nil, &ExecutionError{"TRUST_APPROVAL_MISMATCH"}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	staged, chain, e := material.ProjectBuildFor(ctx, r.runtime, request)
	if e != nil {
		return nil, e
	}
	if e := operationtrust.RecheckAction(ctx, r.runtime.TrustRuntime(), permit, request, stagedReader{staged}); e != nil {
		return nil, e
	}
	modules, e := material.ProjectModulesFor(ctx, r.runtime, request)
	if e != nil {
		return nil, e
	}
	variant, binding, e := material.ProjectVariantFor(r.runtime, request)
	if e != nil {
		return nil, e
	}
	result, e := executeProjectBuild(ctx, r.runtime.ScratchRoot(), staged, chain, modules)
	if e != nil {
		return nil, e
	}
	result.BuildVariant, result.BuildVariantSHA256 = variant, binding
	return &ProcessReceipt{runner: r, request: request.RequestSHA256, result: result}, nil
}
func (p *ProcessReceipt) ResultFor(r *ApprovedRunner, request trustverify.ExecutionRequest) (ProjectProcessResult, error) {
	if p == nil || r == nil || p.runner != r || p.request != request.RequestSHA256 || request.VerifyRequestSHA256() != nil {
		return ProjectProcessResult{}, errors.New("TRUST_EXECUTION_RECEIPT_INVALID")
	}
	return p.result, nil
}
