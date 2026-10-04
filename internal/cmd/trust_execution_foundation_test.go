package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestExecuteFixedActionSuccess(t *testing.T) {
	testfixture.RequireTrustStore(t)
	b := newT6BResolved(t, "normal", "normal")
	defer b.runtime.Close()
	t.Setenv("T6B_EXEC_CANARY", "must-not-reach-approved-process")
	out, err := executeFixedAction(context.Background(), b.runtime, b.resolution, b.op, b.request, b.fixture.persistentApproval(t, b.request))
	if err != nil || string(out) != "approved:literal signed stdin\n" {
		t.Fatalf("executeFixedAction = %q, %v", out, err)
	}
	t6BAssertEmptyScratch(t, b.fixture.scratch)
	// The helper borrows the runtime; it must remain usable by its owner.
	if b.runtime.TrustRuntime() != b.stable {
		t.Fatal("execution closed or replaced the caller's runtime")
	}
}

func TestExecuteFixedActionRejectsUnapprovedOrForeignInput(t *testing.T) {
	testfixture.RequireTrustStore(t)
	b := newT6BResolved(t, "normal", "normal")
	defer b.runtime.Close()
	approval := b.fixture.persistentApproval(t, b.request)
	t.Run("missing-approval", func(t *testing.T) {
		out, err := executeFixedAction(context.Background(), b.runtime, b.resolution, b.op, b.request, trustverify.ApprovalRefs{})
		if err == nil || out != nil {
			t.Fatalf("missing approval = %q, %v", out, err)
		}
		t6BAssertEmptyScratch(t, b.fixture.scratch)
	})
	t.Run("mismatched-signed-approval", func(t *testing.T) {
		other := b.request
		other.TimeoutMillis--
		var err error
		other.RequestSHA256, err = other.ComputeRequestSHA256()
		if err != nil {
			t.Fatal(err)
		}
		out, err := executeFixedAction(context.Background(), b.runtime, b.resolution, b.op, b.request, b.fixture.persistentApproval(t, other))
		if err == nil || out != nil {
			t.Fatalf("mismatched approval = %q, %v", out, err)
		}
		t6BAssertEmptyScratch(t, b.fixture.scratch)
	})
	t.Run("foreign-resolution", func(t *testing.T) {
		foreign := newT6BResolved(t, "normal", "normal")
		defer foreign.runtime.Close()
		out, err := executeFixedAction(context.Background(), b.runtime, foreign.resolution, b.op, b.request, approval)
		if err == nil || out != nil {
			t.Fatalf("foreign resolution = %q, %v", out, err)
		}
		t6BAssertEmptyScratch(t, b.fixture.scratch)
		t6BAssertEmptyScratch(t, foreign.fixture.scratch)
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, err := executeFixedAction(ctx, b.runtime, b.resolution, b.op, b.request, approval)
		if !errors.Is(err, context.Canceled) || out != nil {
			t.Fatalf("canceled execution = %q, %v", out, err)
		}
		t6BAssertEmptyScratch(t, b.fixture.scratch)
	})
	t.Run("closed-runtime", func(t *testing.T) {
		if err := b.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		out, err := executeFixedAction(context.Background(), b.runtime, b.resolution, b.op, b.request, approval)
		if err == nil || err.Error() != "TRUST_RUNTIME_UNAVAILABLE" || out != nil {
			t.Fatalf("closed runtime = %q, %v", out, err)
		}
		t6BAssertEmptyScratch(t, b.fixture.scratch)
	})
}

func TestExecuteFixedActionRetainsNativeConfinement(t *testing.T) {
	testfixture.RequireTrustStore(t)
	b := newT6BResolved(t, "normal", "normal")
	defer b.runtime.Close()
	for _, tc := range []struct {
		name   string
		mutate func(*trustverify.ExecutionRequest)
	}{
		{"signed-tool-drift", func(r *trustverify.ExecutionRequest) {
			r.Tool.BinarySHA256 = evidencecas.Digest([]byte("different signed tool"))
		}},
		{"shell", func(r *trustverify.ExecutionRequest) { r.Action.Shell = true }},
		{"project-directory", func(r *trustverify.ExecutionRequest) { r.WorkingDirectoryScope.Root = "project" }},
		{"timeout-over-five-seconds", func(r *trustverify.ExecutionRequest) { r.TimeoutMillis = 5001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := b.request
			tc.mutate(&request)
			operation := b.op
			operation.Actions = []trustverify.ActionMaterial{{Provider: request.Provider, Action: request.Action, Tool: request.Tool, WorkingDirectoryScope: request.WorkingDirectoryScope, EnvironmentPolicySHA256: request.EnvironmentPolicySHA256, TimeoutMillis: request.TimeoutMillis, Migration: request.Migration}}
			var err error
			request.OperationInputsSHA256, err = trustverify.ComputeOperationInputsSHA256(operation)
			if err != nil {
				if tc.name == "shell" {
					// Shell actions are rejected by the operation schema before
					// they can even receive a valid request digest or approval.
					out, execErr := executeFixedAction(context.Background(), b.runtime, b.resolution, operation, request, b.fixture.persistentApproval(t, b.request))
					if execErr == nil || out != nil {
						t.Fatalf("shell action = %q, %v", out, execErr)
					}
					t6BAssertEmptyScratch(t, b.fixture.scratch)
					return
				}
				t.Fatal(err)
			}
			request.RequestSHA256, err = request.ComputeRequestSHA256()
			if err != nil {
				t.Fatal(err)
			}
			// Sign the changed request, so confinement does not rely on a stale
			// approval or an inconsistent operation/request digest.
			approval := b.fixture.persistentApproval(t, request)
			out, err := executeFixedAction(context.Background(), b.runtime, b.resolution, operation, request, approval)
			if err == nil || out != nil {
				t.Fatalf("%s = %q, %v", tc.name, out, err)
			}
			if tc.name == "signed-tool-drift" && !errors.Is(err, operationtrust.ErrExecutionMaterialUnavailable) {
				t.Fatalf("signed tool drift must reach material verification: %v", err)
			}
			t6BAssertEmptyScratch(t, b.fixture.scratch)
		})
	}
}
