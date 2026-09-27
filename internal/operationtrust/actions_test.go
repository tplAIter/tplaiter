package operationtrust

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestActionGatesFailBeforeAuthorizationOrExecution(t *testing.T) {
	if permits, err := AuthorizeActions(context.Background(), nil, nil, trustverify.OperationInputs{}, nil, nil); err == nil || permits != nil {
		t.Fatalf("invalid gate = %#v, %v", permits, err)
	}
	if err := RecheckAction(context.Background(), nil, nil, trustverify.ExecutionRequest{}, nil); err == nil {
		t.Fatal("nil recheck inputs accepted")
	}
}
