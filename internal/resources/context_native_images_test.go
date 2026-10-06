package resources

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestContextNativeImagesRefuseFabricatedIntent(t *testing.T) {
	for _, p := range []*contextsource.PreparedNativeNew{nil, {}} {
		if _, err := PlanContextNativeGeneratorImages(context.Background(), &trustload.Runtime{}, p); err == nil {
			t.Fatal("fabricated resource authority")
		}
	}
	if _, err := PlanContextNativeGeneratorImages(nil, &trustload.Runtime{}, &contextsource.PreparedNativeNew{}); err == nil {
		t.Fatal("nil context")
	}
}
