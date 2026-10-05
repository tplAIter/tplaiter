package mcpsrv

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

const fakeExe = "tplater-fake"

// newTestClient starts an in-process MCP server with a stub runner
// (execx.RecordingRunner) and connects an in-memory client. A real tplaiter
// binary is unnecessary: the mcp-go transport and handler logic are tested in
// full while the runner script simulates the child process.
func newTestClient(t *testing.T, runner execx.Runner) *client.Client {
	t.Helper()

	srv := New(fakeExe, "test", runner)
	c, err := client.NewInProcessClient(srv.MCP())
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0.0"}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return c
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := mcp.AsTextContent(c); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// envelopeJSON returns the canonical child stdout for op after mutate.
func envelopeJSON(t *testing.T, op resultdto.Operation, mutate func(*resultdto.Result)) string {
	t.Helper()
	env := resultdto.New(op, "test")
	if mutate != nil {
		mutate(&env)
	}
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		t.Fatalf("fixture envelope for %s: %v", op, err)
	}
	return string(raw) + "\n"
}

// structuredEnvelope decodes the structured content of a tool result as a
// result/v1 envelope.
func structuredEnvelope(t *testing.T, res *mcp.CallToolResult) resultdto.Result {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("tool result has no structured content: %s", resultText(t, res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	env, err := resultdto.Decode(raw)
	if err != nil {
		t.Fatalf("structured content is not result/v1: %v\n%s", err, raw)
	}
	return env
}

func callTool(t *testing.T, c *client.Client, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

// TestProtocolListTools checks the complete initialize-to-tools/list cycle and
// the declared expected tool set.
func TestProtocolListTools(t *testing.T) {
	runner := execx.NewRecordingRunner()
	c := newTestClient(t, runner)

	ctx := context.Background()
	res, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}

	want := []string{
		"context", "project_diff", "settings_edit",
		"trust_inspect",
		"repo_add", "repo_list", "repo_update", "repo_remove",
		"template_list", "template_show",
		"project_new", "project_link", "project_verify", "project_check", "deps_verify",
		"run", "settings_list", "settings_set",
		"update", "stats", "gen", "gen_batch", "gen_list",
		"workspace_add_service",
		"lint_template", "init_template",
		"projects_list", "doctor", "ai_gen", "env_setup",
	}
	if len(res.Tools) != len(want) {
		t.Errorf("tool count = %d, want %d", len(res.Tools), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("tool %q is not registered", name)
		}
	}
}

// TestProjectNewAndGenLifecycleFlags checks the public schema and end-to-end
// mapping of lifecycle flags to the CLI. It prevents a field from existing in a
// Go structure while remaining unavailable to an MCP client.
func TestProjectNewAndGenLifecycleFlags(t *testing.T) {
	runner := execx.NewRecordingRunner()
	projectDir := t.TempDir()
	projectArgv := withJSONFlag(argvProjectNewInvocation(projectNewInvocation{Ref: "go/service", Name: "billing", NoHooks: true, NoDepsCheck: true, NoEnvSetup: true, Yes: true, TargetDir: projectDir + "/billing"}))
	genArgv := withJSONFlag(append(argvGen("rust-module", "billing", nil, true), "--dir", projectDir))
	runner.On(fakeExe, projectArgv, execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationProjectNew, func(r *resultdto.Result) {
		r.Project = &resultdto.Project{ID: "billing", Root: projectDir + "/billing"}
	}), ExitCode: 0}})
	runner.On(fakeExe, genArgv, execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenRun, func(r *resultdto.Result) {
		r.Project = &resultdto.Project{ID: "billing", Root: projectDir}
		r.Status = resultdto.StatusChanges
		r.Changes = []resultdto.Change{{Path: "src/billing.rs", Action: "create"}}
		_ = r.SetData(resultdto.GenRunData{Created: []string{"src/billing.rs"}, Edited: []string{}, NoBuild: true})
	}), ExitCode: 0}})
	c := newTestClient(t, runner)

	tools, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	byName := make(map[string]mcp.Tool, len(tools.Tools))
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	for _, field := range []string{"noHooks", "noDepsCheck", "noEnvSetup", "yes"} {
		requireBooleanToolProperty(t, byName["project_new"], field)
	}
	requireBooleanToolProperty(t, byName["gen"], "noBuild")

	projectRes := callTool(t, c, "project_new", map[string]any{
		"ref": "go/service", "name": "billing", "dir": projectDir,
		"noHooks": true, "noDepsCheck": true, "noEnvSetup": true, "yes": true,
	})
	if projectRes.IsError {
		t.Fatalf("project_new returned isError: %s", resultText(t, projectRes))
	}
	if env := structuredEnvelope(t, projectRes); env.Operation != resultdto.OperationProjectNew {
		t.Fatalf("project_new operation=%s", env.Operation)
	}

	genRes := callTool(t, c, "gen", map[string]any{
		"kind": "rust-module", "name": "billing", "dir": projectDir, "noBuild": true,
	})
	if genRes.IsError {
		t.Fatalf("gen returned isError: %s", resultText(t, genRes))
	}
	env := structuredEnvelope(t, genRes)
	if env.Status != resultdto.StatusChanges || len(env.Changes) != 1 {
		t.Fatalf("gen envelope=%+v", env)
	}
}

func requireBooleanToolProperty(t *testing.T, tool mcp.Tool, field string) {
	t.Helper()
	property, ok := tool.InputSchema.Properties[field]
	if !ok {
		t.Fatalf("tool %q does not publish field %q", tool.Name, field)
	}
	schema, ok := property.(map[string]any)
	if !ok || schema["type"] != "boolean" {
		t.Fatalf("tool %q: schema %q = %#v, want boolean", tool.Name, field, property)
	}
	if description, _ := schema["description"].(string); description == "" {
		t.Errorf("tool %q: field %q has no description", tool.Name, field)
	}
}

// TestRepoListSuccess: repo_list passes the child's envelope through as
// structured content with a compact summary, and the child receives --json.
func TestRepoListSuccess(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, withJSONFlag(argvRepoList()), execx.Response{
		Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationRepoList, func(r *resultdto.Result) {
			_ = r.SetData(resultdto.RepoListData{Repositories: []resultdto.RepoInfo{{Alias: "fixture", URL: "file:///srv/git.example.test/t.git", Type: "git", Templates: 1}}})
		}), ExitCode: 0},
	})
	c := newTestClient(t, runner)

	res := callTool(t, c, "repo_list", nil)
	if res.IsError {
		t.Fatalf("repo_list returned isError: %s", resultText(t, res))
	}
	env := structuredEnvelope(t, res)
	var data resultdto.RepoListData
	if err := json.Unmarshal(env.Data, &data); err != nil || len(data.Repositories) != 1 || data.Repositories[0].Alias != "fixture" {
		t.Fatalf("repo_list data=%s err=%v", env.Data, err)
	}
	if text := resultText(t, res); !strings.HasPrefix(text, "repo.list: ok") {
		t.Errorf("summary text = %q", text)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Name != fakeExe {
		t.Fatalf("calls = %#v", runner.Calls)
	}
}

func TestGenBatchSuccess(t *testing.T) {
	runner := execx.NewRecordingRunner()
	dir := t.TempDir()
	operations := []genBatchOperation{
		{Kind: "crud", Name: "Ride", Params: map[string]string{"fields": "status:string"}},
		{Kind: "workflow", Name: "MatchRide"},
	}
	runner.On(fakeExe, withJSONFlag(append(argvGenBatch(operations, false), "--dir", dir)), execx.Response{Result: execx.Result{Stdout: envelopeJSON(t, resultdto.OperationGenBatch, func(r *resultdto.Result) {
		r.Project = &resultdto.Project{ID: "ride", Root: dir}
		r.Status = resultdto.StatusChanges
		r.Changes = []resultdto.Change{{Path: "internal/ride.go", Action: "create"}}
	}), ExitCode: 0}})
	c := newTestClient(t, runner)

	res := callTool(t, c, "gen_batch", map[string]any{
		"dir": dir,
		"operations": []any{
			map[string]any{"kind": "crud", "name": "Ride", "params": map[string]any{"fields": "status:string"}},
			map[string]any{"kind": "workflow", "name": "MatchRide"},
		},
	})
	if res.IsError {
		t.Fatalf("gen_batch returned isError: %s", resultText(t, res))
	}
	if env := structuredEnvelope(t, res); len(env.Changes) != 1 || env.Changes[0].Path != "internal/ride.go" {
		t.Errorf("unexpected envelope: %+v", env)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir == "" {
		t.Errorf("expected one call with workdir, calls = %#v", runner.Calls)
	}
}

// TestTemplateShowFailureEnvelope: a failing child's own typed envelope is
// returned (isError) with its exit-consistent status.
func TestTemplateShowFailureEnvelope(t *testing.T) {
	runner := execx.NewRecordingRunner()
	argv := withJSONFlag(argvTemplateShow("ghost/none"))
	stdout := envelopeJSON(t, resultdto.OperationTemplateShow, func(r *resultdto.Result) {
		r.Status = resultdto.StatusBlocked
		r.Diagnostics = []resultdto.Diagnostic{{Code: "CLI_OPERATION_FAILED", Severity: "error", Message: "the command failed", Details: map[string]any{}}}
	})
	runner.On(fakeExe, argv, execx.Response{
		Result: execx.Result{Stdout: stdout, Stderr: "template not found: ghost/none\n", ExitCode: int(resultdto.ExitOperational)},
		Err:    &execx.ExitError{Name: fakeExe, Args: argv, ExitCode: int(resultdto.ExitOperational)},
	})
	c := newTestClient(t, runner)

	res := callTool(t, c, "template_show", map[string]any{"ref": "ghost/none"})
	if !res.IsError {
		t.Fatalf("expected isError, got success: %s", resultText(t, res))
	}
	env := structuredEnvelope(t, res)
	if env.Status != resultdto.StatusBlocked || env.Diagnostics[0].Code != "CLI_OPERATION_FAILED" {
		t.Fatalf("envelope=%+v", env)
	}
	if strings.Contains(resultText(t, res), "ghost") {
		t.Errorf("raw child stderr leaked into the summary: %q", resultText(t, res))
	}
}

// TestBrokenChildContractIsNeverForwarded: stdout that is not a matching
// envelope becomes MCP_CONTRACT_INVALID, and raw child output never reaches
// the client. A whole known trust line becomes its code.
func TestBrokenChildContractIsNeverForwarded(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, stderr string
		exit                 int
		want                 string
	}{
		{"plain text", "secret-canary\n", "", 0, "MCP_CONTRACT_INVALID"},
		{"wrong operation", envelopeJSON(t, resultdto.OperationRepoList, nil), "", 0, "MCP_CONTRACT_INVALID"},
		{"status/exit mismatch", envelopeJSON(t, resultdto.OperationTemplateShow, nil), "", int(resultdto.ExitTrust), "MCP_CONTRACT_INVALID"},
		{"unregistered exit", "", "secret-canary", 42, "MCP_CONTRACT_INVALID"},
		{"known trust line", "", "error: trustload: TRUST_ANCHOR_MISSING\n", 1, "TRUST_ANCHOR_MISSING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := execx.NewRecordingRunner()
			argv := withJSONFlag(argvTemplateShow("x"))
			var runErr error
			if tc.exit != 0 {
				runErr = &execx.ExitError{Name: fakeExe, Args: argv, ExitCode: tc.exit}
			}
			runner.On(fakeExe, argv, execx.Response{Result: execx.Result{Stdout: tc.stdout, Stderr: tc.stderr, ExitCode: tc.exit}, Err: runErr})
			c := newTestClient(t, runner)
			res := callTool(t, c, "template_show", map[string]any{"ref": "x"})
			if !res.IsError {
				t.Fatal("broken contract returned success")
			}
			env := structuredEnvelope(t, res)
			if env.Operation != resultdto.OperationTemplateShow || env.Diagnostics[0].Code != tc.want {
				t.Fatalf("envelope=%+v", env)
			}
			raw, _ := json.Marshal(res)
			if strings.Contains(string(raw), "secret-canary") {
				t.Fatalf("raw child output leaked: %s", raw)
			}
		})
	}
}

// TestLaunchFailure: child launch failure (binary absent, exitCode -1 without
// ExitError) yields a fixed MCP_UNAVAILABLE envelope.
func TestLaunchFailure(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, withJSONFlag(argvProjectsList()), execx.Response{
		Result: execx.Result{ExitCode: -1},
		Err:    notFoundError{},
	})
	c := newTestClient(t, runner)

	res := callTool(t, c, "projects_list", nil)
	if !res.IsError {
		t.Fatalf("expected isError on launch failure")
	}
	env := structuredEnvelope(t, res)
	if env.Diagnostics[0].Code != "MCP_UNAVAILABLE" || env.Status != resultdto.StatusFailed {
		t.Errorf("launch failure envelope: %+v", env)
	}
}

// TestInvalidDirectoryArgument: a directory that does not exist is rejected
// before any child starts, with a structured MCP_INVALID_ARGUMENT envelope.
func TestInvalidDirectoryArgument(t *testing.T) {
	runner := execx.NewRecordingRunner()
	c := newTestClient(t, runner)
	res := callTool(t, c, "gen_list", map[string]any{"dir": "/nonexistent/tplaiter-test-dir"})
	env := structuredEnvelope(t, res)
	if !res.IsError || env.Diagnostics[0].Code != "MCP_INVALID_ARGUMENT" || len(runner.Calls) != 0 {
		t.Fatalf("res=%+v env=%+v calls=%d", res, env, len(runner.Calls))
	}
}

// TestTrustInspectAdaptsBareBinding: trust inspect prints the bare binding;
// the tool wraps it into a trust.inspect envelope.
func TestTrustInspectAdaptsBareBinding(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, argvTrustInspect(), execx.Response{Result: execx.Result{Stdout: `{"id":"oss","evidenceClass":"simulated"}` + "\n"}})
	c := newTestClient(t, runner)
	res := callTool(t, c, "trust_inspect", nil)
	if res.IsError {
		t.Fatalf("trust_inspect isError: %s", resultText(t, res))
	}
	env := structuredEnvelope(t, res)
	var data resultdto.TrustInspectData
	if err := json.Unmarshal(env.Data, &data); err != nil || data.Binding["id"] != "oss" {
		t.Fatalf("data=%s err=%v", env.Data, err)
	}
}

type notFoundError struct{}

func (notFoundError) Error() string { return "execx: run \"tplater-fake\": executable file not found" }
