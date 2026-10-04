package cmd

import (
	"context"
	"errors"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// executeFixedAction executes one persistently approved native snapshot action.
// The caller owns the installed runtime and verified source resolution. This
// helper neither selects trust material nor supplies approval; the fixed material
// bridge retains its provider directory, no-shell and five-second constraints.
// Only stdout authenticated by the execution receipt is returned, and failures
// return no output. The caller remains responsible for closing the runtime.
func executeFixedAction(ctx context.Context, runtime *trustload.Runtime, resolution *trustverify.VerifiedResolution, operation trustverify.OperationInputs, request trustverify.ExecutionRequest, approval trustverify.ApprovalRefs) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("TRUST_REQUEST_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stable := runtime.TrustRuntime()
	if stable == nil {
		return nil, &execx.ExecutionError{Code: "TRUST_RUNTIME_UNAVAILABLE"}
	}
	permits, err := operationtrust.AuthorizeActions(ctx, stable, resolution, operation, []trustverify.ExecutionRequest{request}, []trustverify.ApprovalRefs{approval})
	if err != nil {
		return nil, err
	}
	selection, err := operationtrust.ResolveFixedComposition(ctx, stable, resolution, operation, request)
	if err != nil {
		return nil, err
	}
	material, err := operationtrust.BindExecutionMaterial(ctx, stable, resolution, operation, request, selection)
	if err != nil {
		return nil, err
	}
	runner, err := execx.NewApprovedRunner(runtime)
	if err != nil {
		return nil, err
	}
	receipt, err := runner.Execute(ctx, permits[0], request, material)
	if err != nil {
		return nil, err
	}
	return receipt.StdoutFor(runner, request)
}

// trustExecutionUnavailable keeps stock command composition closed until a
// lifecycle owner supplies the separately approved fixed C/T3 action.
func trustExecutionUnavailable() error {
	return errors.Join(trustload.ErrProvenanceUnavailable, errors.New("TRUST_EXECUTION_UNAVAILABLE"))
}
