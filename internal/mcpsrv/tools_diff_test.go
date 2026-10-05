package mcpsrv

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// This tests the no-child control gate only. Runtime proof is the installed
// CLI/MCP process fixture in cmd, not this RecordingRunner.
func TestDiffUnknownControlsNeverLaunch(t *testing.T) {
	runner := execx.NewRecordingRunner()
	client := newTestClient(t, runner)
	for _, key := range []string{"execute", "sourceInput", "approval", "trusted", "ProjectContext", "exit_code"} {
		res := callTool(t, client, "project_diff", map[string]any{key: true})
		if !res.IsError {
			t.Fatalf("accepted %s", key)
		}
	}
	if len(runner.Calls) != 0 {
		t.Fatal("unknown controls launched a child")
	}
}
