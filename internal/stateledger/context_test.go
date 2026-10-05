package stateledger

import (
	"context"
	"errors"
	"testing"
)

func TestMigrationContextCancelledBeforeIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanContext(ctx, "/unavailable", Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ApplyPlanContext(ctx, "/unavailable", Options{}, "digest"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
