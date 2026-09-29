package operationtrust

import (
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestExecutionMaterialZeroFails(t *testing.T) {
	if _, e := ResolveFixedComposition(nil, nil, nil, structOperation(), structRequest()); e == nil { //nolint:staticcheck // deliberately exercises nil-context rejection
		t.Fatal("zero accepted")
	}
}

// The operation digest alone is not a material capability: the three request
// identity fields must agree with each other and with the live runtime before
// snapshot convention processing can select anything.
func TestExecutionMaterialRejectsOperationIdentityMismatch(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t)
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stable := r.TrustRuntime()
	resolution, err := stable.VerifySubject(context.Background(), f.target, f.targetRefs)
	if err != nil {
		t.Fatal(err)
	}
	op, request, _ := t5DActionInputs(t, stable.Binding(), f.source, f.target, r.ProjectContext().ProjectID)
	for _, tc := range []struct {
		name   string
		mutate func(*trustverify.OperationInputs, *trustverify.ExecutionRequest)
	}{
		{"project", func(o *trustverify.OperationInputs, _ *trustverify.ExecutionRequest) { o.ProjectID = "other-project" }},
		{"scope", func(o *trustverify.OperationInputs, _ *trustverify.ExecutionRequest) { o.Scope = "run" }},
		{"profile", func(o *trustverify.OperationInputs, _ *trustverify.ExecutionRequest) {
			o.ProfileBindingSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			badOp, badRequest := cloneOperation(op), cloneRequest(request)
			tc.mutate(&badOp, &badRequest)
			d, err := trustverify.ComputeOperationInputsSHA256(badOp)
			if err != nil {
				t.Fatal(err)
			}
			badRequest.OperationInputsSHA256 = d
			badRequest.RequestSHA256, err = badRequest.ComputeRequestSHA256()
			if err != nil {
				t.Fatal(err)
			}
			if got, err := ResolveFixedComposition(context.Background(), stable, resolution, badOp, badRequest); !errors.Is(err, ErrExecutionMaterialUnavailable) || got != nil {
				t.Fatalf("mismatched %s operation selected: %#v, %v", tc.name, got, err)
			}
		})
	}
}
func structOperation() trustverify.OperationInputs { return trustverify.OperationInputs{} }
func structRequest() trustverify.ExecutionRequest  { return trustverify.ExecutionRequest{} }

// This is deliberately the installed C/T3 fixture, rather than a hand-made
// Runtime.  Its signed native snapshot has no execution convention and must
// therefore fail before any stage can exist.
func TestExecutionMaterialRejectsSignedSnapshotWithoutConvention(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t)
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stable := r.TrustRuntime()
	resolution, err := stable.VerifySubject(context.Background(), f.target, f.targetRefs)
	if err != nil {
		t.Fatal(err)
	}
	op, request, _ := t5DActionInputs(t, stable.Binding(), f.source, f.target, r.ProjectContext().ProjectID)
	if got, err := ResolveFixedComposition(context.Background(), stable, resolution, op, request); !errors.Is(err, ErrExecutionMaterialUnavailable) || got != nil {
		t.Fatalf("unsigned convention admission = %#v, %v", got, err)
	}
	t5DAssertEmptyDir(t, f.scratch)
}
