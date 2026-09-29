package deps

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func TestInstallForIsExecutionClosed(t *testing.T) {
	r := &closedSpy{}
	_, e := Install(context.Background(), r, NewUI(io.Discard, ui.Palette{}), manifest.Tool{Name: "../host", Install: manifest.ToolInstall{Brew: "x"}}, func() bool { return true })
	if !errors.Is(e, ErrExecutionUnavailable) || r.look != 0 || r.run != 0 {
		t.Fatalf("%v look=%d run=%d", e, r.look, r.run)
	}
	if InstallPlan(manifest.Tool{Install: manifest.ToolInstall{Brew: "x"}}, Platform{GOOS: "darwin", HasBrew: true}).Kind != ActionBrew {
		t.Fatal("pure plan")
	}
}
