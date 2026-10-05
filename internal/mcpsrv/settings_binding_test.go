package mcpsrv

import (
	"encoding/json"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestNativeSettingsHandlersBindContextAndDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		tool string
		args map[string]any
		argv []string
		op   resultdto.Operation
	}{
		{"settings_list", map[string]any{"dir": dir, "projectContext": "bound"}, []string{"settings", "list", "--dir", dir, "--project-context", "bound"}, resultdto.OperationSettingsShow},
		{"settings_set", map[string]any{"dir": dir, "projectContext": "bound", "values": map[string]string{"label": "--json"}, "dryRun": true}, []string{"settings", "set", "label=--json", "--yes", "--dir", dir, "--project-context", "bound", "--dry-run"}, resultdto.OperationSettingsSet},
		{"settings_edit", map[string]any{"dir": dir, "projectContext": "bound", "group": "label", "value": "--json", "dryRun": true}, []string{"settings", "edit", "label", "--value=--json", "--yes", "--dir", dir, "--project-context", "bound", "--dry-run"}, resultdto.OperationSettingsReanswer},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			runner := execx.NewRecordingRunner()
			runner.On(fakeExe, withJSONFlag(tc.argv), execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, tc.op, func(r *resultdto.Result) { r.Project = &resultdto.Project{ID: "bound", Root: dir} })}})
			result := callTool(t, newTestClient(t, runner), tc.tool, tc.args)
			if result.IsError || len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir != dir {
				t.Fatalf("binding: %s %#v", resultText(t, result), runner.Calls)
			}
		})
	}
}

func TestNativeSettingsHandlersRejectGroupControlsBeforeSpawn(t *testing.T) {
	for _, group := range []string{"", "--json", " --dir", "label=other"} {
		for _, tool := range []string{"settings_set", "settings_edit"} {
			t.Run(tool+group, func(t *testing.T) {
				runner := execx.NewRecordingRunner()
				args := map[string]any{"dir": t.TempDir(), "projectContext": "bound", "group": group, "value": "x", "values": map[string]string{group: "x"}}
				result := callTool(t, newTestClient(t, runner), tool, args)
				env := structuredEnvelope(t, result)
				if !result.IsError || len(runner.Calls) != 0 || env.Diagnostics[0].Code != "MCP_INVALID_ARGUMENT" {
					t.Fatalf("group control: %+v %#v", env, runner.Calls)
				}
			})
		}
	}
}

func TestNativeSettingsToolSchemas(t *testing.T) {
	srv := New("/nonexistent/tplaiter", "test", nil)
	for tool, op := range map[string]resultdto.Operation{"settings_list": resultdto.OperationSettingsShow, "settings_set": resultdto.OperationSettingsSet, "settings_edit": resultdto.OperationSettingsReanswer} {
		registered := srv.MCP().ListTools()[tool].Tool
		schema := compileToolSchema(t, registered.RawOutputSchema)
		validateStructured(t, schema, srv.argumentFailure(op, "dir"), "argument refusal")
		env := resultdto.New(op, "test")
		env.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
		validateStructured(t, schema, structuredResult(env, false), "success")
		raw, err := json.Marshal(registered)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("settings-tool-delta %s", raw)
	}
}
