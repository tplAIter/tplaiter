package resources

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestRecordedResourceProjectionRejectsFabricatedCarrier(t *testing.T) {
	if _, err := PlanContextNativeSnapshotGeneratorImages(context.Background(), &trustload.Runtime{}, &contextsource.PreparedNativeSnapshot{}); err == nil {
		t.Fatal("fabricated recorded snapshot produced resources")
	}
}
