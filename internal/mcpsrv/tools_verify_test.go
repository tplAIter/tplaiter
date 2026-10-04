package mcpsrv

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// This is a transport refusal test, not backend acceptance evidence.
func TestReadonlyToolsPreserveTargetAndTypedFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   resultdto.Operation
		argv []string
	}{
		{"project_verify", resultdto.OperationProjectVerify, []string{"verify"}},
		{"project_check", resultdto.OperationProjectCheck, []string{"check"}},
		{"deps_verify", resultdto.OperationDepsVerify, []string{"deps", "verify"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			target := "/installed/project-root"
			argv := append(append([]string(nil), tc.argv...), "--dir", target, "--project-context", "b", "--offline=true", "--json")
			runner := execx.NewRecordingRunner()
			runner.On(fakeExe, argv, execx.Response{Result: execx.Result{ExitCode: 5, Stdout: envelopeJSON(t, tc.op, func(r *resultdto.Result) {
				r.Status = resultdto.StatusBlocked
				r.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_PROJECT_CONTEXT_MISMATCH", Severity: "error", Message: "refused"}}
			})}})
			c := newTestClient(t, runner)
			res := callTool(t, c, tc.name, map[string]any{"dir": cwd, "targetDir": target, "projectContext": "b"})
			env := structuredEnvelope(t, res)
			if !res.IsError || env.Operation != tc.op || env.Project != nil || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != "TRUST_PROJECT_CONTEXT_MISMATCH" {
				t.Fatalf("failure: %+v", env)
			}
			if len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir != cwd || !reflect.DeepEqual(runner.Calls[0].Args, argv) {
				t.Fatalf("target/cwd mixed: %+v", runner.Calls)
			}
		})
	}
}

func TestReadonlyOutputSchemasContainTypedData(t *testing.T) {
	srv := New("/unavailable", "test", nil)
	for _, tc := range []struct {
		name string
		op   resultdto.Operation
		data any
	}{
		{"project_verify", resultdto.OperationProjectVerify, resultdto.ProjectVerifyData{Offline: true, DependencyState: "not-applicable"}},
		{"project_check", resultdto.OperationProjectCheck, resultdto.ProjectCheckData{Offline: true, APIVersion: "tplaiter.dev/project-check/v1", Status: "pass", Managed: resultdto.ManagedCheckData{State: "not-applicable", Modified: []string{}, Missing: []string{}, Invalid: []string{}}, Findings: []string{}, Verify: resultdto.ProjectVerifyData{Offline: true, DependencyState: "not-applicable"}}},
		{"deps_verify", resultdto.OperationDepsVerify, resultdto.DepsVerifyData{Offline: true, Verified: true}},
	} {
		schema := compileToolSchema(t, srv.MCP().ListTools()[tc.name].Tool.RawOutputSchema)
		env := resultdto.New(tc.op, "test")
		env.Project = &resultdto.Project{ID: "installed", Root: "/installed/root"}
		if err := env.SetData(tc.data); err != nil {
			t.Fatal(err)
		}
		validateStructured(t, schema, structuredResult(env, false), tc.name)
		env.Data = []byte(`{"offline":true,"unexpected":"must reject"}`)
		if validateAgainst(schema, structuredResult(env, false)) == nil {
			t.Fatalf("%s schema accepts unknown/incomplete data", tc.name)
		}
		validateStructured(t, schema, srv.transportFailure(tc.op, "MCP_CANCELLED", 0), "cancelled")
	}
}

// Real process cancellation verifies typed transport failures for all new
// operation identities without crediting the helper as project authority.
func TestReadonlyTransportCancellation(t *testing.T) {
	for _, op := range []resultdto.Operation{resultdto.OperationProjectVerify, resultdto.OperationProjectCheck, resultdto.OperationDepsVerify} {
		t.Run(string(op), func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "pids")
			s := directHelperServer(t, Limits{DefaultTimeout: time.Minute, KillGrace: 500 * time.Millisecond}, helperEnv+"=spawn-grandchild", "TPLAITER_TEST_PIDFILE="+pidFile)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *mcp.CallToolResult, 1)
			go func() { done <- s.callStructured(ctx, op, "", []string{"verify", "--offline"}, shortCall) }()
			leader, grandchild := readPids(t, pidFile)
			cancel()
			var res *mcp.CallToolResult
			select {
			case res = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("cancelled child did not terminate")
			}
			env := structuredEnvelope(t, res)
			if !res.IsError || env.Operation != op || env.Status != resultdto.StatusFailed || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != "MCP_CANCELLED" {
				t.Fatalf("cancellation: %+v", env)
			}
			requireGone(t, -leader, "process group")
			requireGone(t, grandchild, "grandchild")
		})
	}
}
