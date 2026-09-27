package operationtrust

import (
	"context"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestPreparedZeroValuesNeverValidate(t *testing.T) {
	if (&PreparedNew{}).ValidFor(&trustverify.Runtime{}) {
		t.Fatal("zero PreparedNew validated")
	}
	if (&PreparedUpdate{}).ValidFor(&trustverify.Runtime{}) {
		t.Fatal("zero PreparedUpdate validated")
	}
}

func TestPreparationRejectsNilRuntimeBeforeSourceOrScratch(t *testing.T) {
	if _, err := PrepareNew(context.Background(), nil, PrepareNewInput{RendererVersion: "v1"}); err == nil {
		t.Fatal("nil runtime accepted")
	}
	if _, err := PrepareUpdate(context.Background(), nil, PrepareUpdateInput{RendererVersion: "v1", PreimageSHA256: "sha256:" + strings.Repeat("0", 64)}); err == nil {
		t.Fatal("nil update runtime accepted")
	}
}
