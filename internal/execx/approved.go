package execx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type (
	ApprovedRunner   struct{ runtime *trustload.Runtime }
	ExecutionReceipt struct {
		runner  *ApprovedRunner
		request string
		stdout  []byte
		digest  string
	}
)
type ExecutionError struct{ Code string }

func (e *ExecutionError) Error() string {
	if e == nil || e.Code == "" {
		return "TRUST_EXECUTION_FAILED"
	}
	return e.Code
}

func NewApprovedRunner(r *trustload.Runtime) (*ApprovedRunner, error) {
	if r == nil || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || r.TrustRuntime() == nil || r.ScratchRoot() == "" {
		return nil, &ExecutionError{"TRUST_EXECUTION_UNAVAILABLE"}
	}
	return &ApprovedRunner{runtime: r}, nil
}

func (r *ApprovedRunner) Execute(ctx context.Context, permit *trustverify.ExecutionPermit, request trustverify.ExecutionRequest, material *operationtrust.ExecutionMaterial) (*ExecutionReceipt, error) {
	if ctx == nil || r == nil || r.runtime == nil || permit == nil || material == nil {
		return nil, &ExecutionError{"TRUST_APPROVAL_MISMATCH"}
	}
	stable, scratch := r.runtime.TrustRuntime(), r.runtime.ScratchRoot()
	if stable == nil || scratch == "" {
		return nil, &ExecutionError{"TRUST_RUNTIME_UNAVAILABLE"}
	}
	staged, err := material.StagedFor(ctx, stable, request)
	if err != nil {
		return nil, &ExecutionError{"TRUST_EXECUTION_MATERIAL_UNAVAILABLE"}
	}
	if err = operationtrust.RecheckAction(ctx, stable, permit, request, stagedReader{staged}); err != nil {
		return nil, &ExecutionError{"TRUST_APPROVAL_MISMATCH"}
	}
	out, err := executeApproved(ctx, scratch, staged)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(out)
	return &ExecutionReceipt{runner: r, request: request.RequestSHA256, stdout: append([]byte(nil), out...), digest: "sha256:" + hex.EncodeToString(h[:])}, nil
}

func (r *ExecutionReceipt) StdoutFor(runner *ApprovedRunner, request trustverify.ExecutionRequest) ([]byte, error) {
	if r == nil || runner == nil || r.runner != runner || r.request != request.RequestSHA256 {
		return nil, errors.New("TRUST_EXECUTION_RECEIPT_INVALID")
	}
	return append([]byte(nil), r.stdout...), nil
}

type stagedReader struct{ m trustverify.StagedMaterial }

func (s stagedReader) Stage(context.Context, trustverify.ExecutionRequest) (trustverify.StagedMaterial, error) {
	return s.m, nil
}
