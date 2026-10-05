package mcpsrv

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestGenHandlersPassResolvedDirectoryControl(t *testing.T) {
	dir := t.TempDir()
	operations := []genBatchOperation{{Kind: "crud", Name: "Ride"}}
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, withJSONFlag(append(argvGen("crud", "Ride", nil, true), "--dir", dir)), execx.Response{
		Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenRun, func(r *resultdto.Result) {
			r.Project = &resultdto.Project{ID: "ride", Root: dir}
		})},
	})
	runner.On(fakeExe, withJSONFlag(append(argvGenBatch(operations, true), "--dir", dir)), execx.Response{
		Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenBatch, func(r *resultdto.Result) {
			r.Project = &resultdto.Project{ID: "ride", Root: dir}
		})},
	})
	runner.On(fakeExe, withJSONFlag(append(argvGenList(), "--dir", dir)), execx.Response{
		Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenList, func(r *resultdto.Result) {
			r.Project = &resultdto.Project{ID: "ride", Root: dir}
		})},
	})
	c := newTestClient(t, runner)

	for _, tc := range []struct {
		name string
		args map[string]any
		want resultdto.Operation
	}{
		{name: "gen", args: map[string]any{"dir": dir, "kind": "crud", "name": "Ride", "noBuild": true}, want: resultdto.OperationGenRun},
		{name: "gen_batch", args: map[string]any{"dir": dir, "operations": []any{map[string]any{"kind": "crud", "name": "Ride"}}, "noBuild": true}, want: resultdto.OperationGenBatch},
		{name: "gen_list", args: map[string]any{"dir": dir}, want: resultdto.OperationGenList},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := callTool(t, c, tc.name, tc.args)
			if res.IsError {
				t.Fatalf("%s returned isError: %s", tc.name, resultText(t, res))
			}
			if env := structuredEnvelope(t, res); env.Operation != tc.want {
				t.Fatalf("operation=%s, want %s", env.Operation, tc.want)
			}
		})
	}

	if len(runner.Calls) != 3 {
		t.Fatalf("calls=%d, want 3: %#v", len(runner.Calls), runner.Calls)
	}
	for _, call := range runner.Calls {
		if call.Opts.Dir != dir {
			t.Errorf("child cwd=%q, want %q", call.Opts.Dir, dir)
		}
		found := false
		for i := 0; i+1 < len(call.Args); i++ {
			if call.Args[i] == "--dir" && call.Args[i+1] == dir {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("argv does not carry bound directory control: %#v", call.Args)
		}
	}
}

func TestGenHandlersRejectReservedParamsBeforeSpawn(t *testing.T) {
	for _, control := range []string{"project-context", "dir", "no-build", "format", "hooks", "json", "help", "operations"} {
		for _, tool := range []string{"gen", "gen_batch"} {
			t.Run(tool+"/"+control, func(t *testing.T) {
				runner := execx.NewRecordingRunner()
				c := newTestClient(t, runner)
				params := map[string]any{control: "collision"}
				args := map[string]any{"dir": t.TempDir(), "kind": "crud", "name": "Ride", "params": params}
				if tool == "gen_batch" {
					args = map[string]any{"dir": args["dir"], "operations": []any{map[string]any{"kind": "crud", "name": "Ride", "params": params}}}
				}
				res := callTool(t, c, tool, args)
				env := structuredEnvelope(t, res)
				if !res.IsError || env.Diagnostics[0].Code != "MCP_INVALID_ARGUMENT" || len(runner.Calls) != 0 {
					t.Fatalf("res=%+v env=%+v calls=%d", res, env, len(runner.Calls))
				}
			})
		}
	}
}

func TestGenHandlersKeepDistinctParamNames(t *testing.T) {
	dir := t.TempDir()
	params := map[string]string{"Dir": "value", "project_context": "value"}
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, withJSONFlag(append(argvGen("crud", "Ride", params, true), "--dir", dir)), execx.Response{
		Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenRun, func(r *resultdto.Result) {
			r.Project = &resultdto.Project{ID: "ride", Root: dir}
		})},
	})
	c := newTestClient(t, runner)
	res := callTool(t, c, "gen", map[string]any{
		"dir": dir, "kind": "crud", "name": "Ride", "params": map[string]any{"Dir": "value", "project_context": "value"}, "noBuild": true,
	})
	if res.IsError || len(runner.Calls) != 1 {
		t.Fatalf("distinct params rejected: %s calls=%d", resultText(t, res), len(runner.Calls))
	}
}

func TestGenForeignDirectoryPreservesTypedRefusal(t *testing.T) {
	boundProject := t.TempDir()
	foreignProject := t.TempDir()
	argv := withJSONFlag(append(argvGen("crud", "Ride", nil, true), "--dir", foreignProject))
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, argv, execx.Response{
		Result: execx.Result{
			Stdout: envelopeJSON(t, resultdto.OperationGenRun, func(r *resultdto.Result) {
				r.Status = resultdto.StatusBlocked
				r.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_PROJECT_CONTEXT_MISMATCH", Severity: "error", Message: "project context mismatch", Details: map[string]any{}}}
			}),
			ExitCode: int(resultdto.ExitTrust),
		},
	})
	c := newTestClient(t, runner)
	res := callTool(t, c, "gen", map[string]any{
		"dir": foreignProject, "kind": "crud", "name": "Ride", "noBuild": true,
	})

	env := structuredEnvelope(t, res)
	if !res.IsError || env.Status != resultdto.StatusBlocked || env.Diagnostics[0].Code != "TRUST_PROJECT_CONTEXT_MISMATCH" {
		t.Fatalf("typed refusal was not preserved: %+v", env)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir != foreignProject {
		t.Fatalf("bound=%q foreign=%q calls=%#v", boundProject, foreignProject, runner.Calls)
	}
}
