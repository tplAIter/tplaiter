package mcpsrv

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
)

const fakeExe = "tplater-fake"

// newTestClient поднимает MCP-сервер in-process с подставным раннером
// (execx.RecordingRunner) и подключает к нему in-memory клиента. Реальный
// бинарник tplater не требуется: транспорт mcp-go и логика хендлеров
// проверяются целиком, а подпроцесс сымитирован скриптом раннера.
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

// TestProtocolListTools проверяет полный цикл initialize → tools/list и что
// заявлен ожидаемый состав tools.
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
		"repo_add", "repo_list", "repo_update", "repo_remove",
		"template_list", "template_show",
		"project_new", "run", "settings_list", "settings_set",
		"update", "stats", "gen", "gen_batch", "gen_list",
		"workspace_add_service",
		"lint_template", "init_template",
		"projects_list", "doctor", "ai_gen", "env_setup",
	}
	if len(res.Tools) != len(want) {
		t.Errorf("число tools = %d, want %d", len(res.Tools), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("tool %q не зарегистрирован", name)
		}
	}
}

// TestProjectNewAndGenLifecycleFlags проверяет публичную schema и сквозной
// маппинг lifecycle-флагов к CLI. Это защищает от ситуации, когда поле есть в
// Go-структуре, но не доступно MCP-клиенту.
func TestProjectNewAndGenLifecycleFlags(t *testing.T) {
	runner := execx.NewRecordingRunner()
	projectArgv := argvProjectNew("go/service", "billing", nil, false, true, true, true, true, 0)
	genArgv := argvGen("rust-module", "billing", nil, true)
	runner.On(fakeExe, projectArgv, execx.Response{Result: execx.Result{Stdout: "проект создан\n", ExitCode: 0}})
	runner.On(fakeExe, genArgv, execx.Response{Result: execx.Result{Stdout: "файл создан\n", ExitCode: 0}})
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

	projectReq := mcp.CallToolRequest{}
	projectReq.Params.Name = "project_new"
	projectReq.Params.Arguments = map[string]any{
		"ref": "go/service", "name": "billing", "dir": t.TempDir(),
		"noHooks": true, "noDepsCheck": true, "noEnvSetup": true, "yes": true,
	}
	projectRes, err := c.CallTool(context.Background(), projectReq)
	if err != nil {
		t.Fatalf("CallTool project_new: %v", err)
	}
	if projectRes.IsError {
		t.Fatalf("project_new вернул isError: %s", resultText(t, projectRes))
	}

	genReq := mcp.CallToolRequest{}
	genReq.Params.Name = "gen"
	genReq.Params.Arguments = map[string]any{
		"kind": "rust-module", "name": "billing", "dir": t.TempDir(), "noBuild": true,
	}
	genRes, err := c.CallTool(context.Background(), genReq)
	if err != nil {
		t.Fatalf("CallTool gen: %v", err)
	}
	if genRes.IsError {
		t.Fatalf("gen вернул isError: %s", resultText(t, genRes))
	}
}

func requireBooleanToolProperty(t *testing.T, tool mcp.Tool, field string) {
	t.Helper()
	property, ok := tool.InputSchema.Properties[field]
	if !ok {
		t.Fatalf("tool %q не публикует поле %q", tool.Name, field)
	}
	schema, ok := property.(map[string]any)
	if !ok || schema["type"] != "boolean" {
		t.Fatalf("tool %q: schema %q = %#v, want boolean", tool.Name, field, property)
	}
	if description, _ := schema["description"].(string); description == "" {
		t.Errorf("tool %q: у поля %q нет описания", tool.Name, field)
	}
}

// TestRepoListSuccess: repo_list на пустом состоянии (сымитировано раннером) →
// НЕ isError, текст содержит вывод подпроцесса, а сам подпроцесс вызван с
// корректным argv.
func TestRepoListSuccess(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, argvRepoList(), execx.Response{
		Result: execx.Result{Stdout: "нет добавленных репозиториев\n", ExitCode: 0},
	})
	c := newTestClient(t, runner)

	req := mcp.CallToolRequest{}
	req.Params.Name = "repo_list"
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool repo_list: %v", err)
	}
	if res.IsError {
		t.Fatalf("repo_list вернул isError: %s", resultText(t, res))
	}
	if !strings.Contains(resultText(t, res), "нет добавленных репозиториев") {
		t.Errorf("текст результата не содержит вывод: %q", resultText(t, res))
	}

	if len(runner.Calls) != 1 {
		t.Fatalf("ожидался 1 вызов подпроцесса, получено %d", len(runner.Calls))
	}
	if got := runner.Calls[0]; got.Name != fakeExe {
		t.Errorf("вызван %q, want %q", got.Name, fakeExe)
	}
}

func TestGenBatchSuccess(t *testing.T) {
	runner := execx.NewRecordingRunner()
	operations := []genBatchOperation{
		{Kind: "crud", Name: "Ride", Params: map[string]string{"fields": "status:string"}},
		{Kind: "workflow", Name: "MatchRide"},
	}
	argv := argvGenBatch(operations, false)
	runner.On(fakeExe, argv, execx.Response{Result: execx.Result{Stdout: "создан internal/ride.go\n", ExitCode: 0}})
	c := newTestClient(t, runner)

	req := mcp.CallToolRequest{}
	req.Params.Name = "gen_batch"
	req.Params.Arguments = map[string]any{
		"dir": t.TempDir(),
		"operations": []any{
			map[string]any{"kind": "crud", "name": "Ride", "params": map[string]any{"fields": "status:string"}},
			map[string]any{"kind": "workflow", "name": "MatchRide"},
		},
	}
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool gen_batch: %v", err)
	}
	if res.IsError {
		t.Fatalf("gen_batch вернул isError: %s", resultText(t, res))
	}
	if !strings.Contains(resultText(t, res), "создан internal/ride.go") {
		t.Errorf("неожиданный вывод: %q", resultText(t, res))
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Opts.Dir == "" {
		t.Errorf("ожидался один вызов с workdir, calls = %#v", runner.Calls)
	}
}

// TestTemplateShowNotFound: ненулевой код возврата подпроцесса → isError с
// полным stderr в тексте.
func TestTemplateShowNotFound(t *testing.T) {
	runner := execx.NewRecordingRunner()
	argv := argvTemplateShow("ghost/none")
	runner.On(fakeExe, argv, execx.Response{
		Result: execx.Result{Stderr: "шаблон не найден: ghost/none\n", ExitCode: 1},
		Err:    &execx.ExitError{Name: fakeExe, Args: argv, ExitCode: 1, Stderr: "шаблон не найден: ghost/none\n"},
	})
	c := newTestClient(t, runner)

	req := mcp.CallToolRequest{}
	req.Params.Name = "template_show"
	req.Params.Arguments = map[string]any{"ref": "ghost/none"}
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool template_show: %v", err)
	}
	if !res.IsError {
		t.Fatalf("ожидался isError, получен успех: %s", resultText(t, res))
	}
	text := resultText(t, res)
	if !strings.Contains(text, "шаблон не найден") {
		t.Errorf("isError не содержит stderr подпроцесса: %q", text)
	}
	if !strings.Contains(text, "код возврата 1") {
		t.Errorf("isError не содержит код возврата: %q", text)
	}
}

// TestLaunchFailure: сбой запуска подпроцесса (бинарник не найден, exitCode -1
// без ExitError) → isError с текстом ошибки запуска.
func TestLaunchFailure(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.On(fakeExe, argvProjectsList(), execx.Response{
		Result: execx.Result{ExitCode: -1},
		Err:    notFoundError{},
	})
	c := newTestClient(t, runner)

	req := mcp.CallToolRequest{}
	req.Params.Name = "projects_list"
	res, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool projects_list: %v", err)
	}
	if !res.IsError {
		t.Fatalf("ожидался isError при сбое запуска")
	}
	if !strings.Contains(resultText(t, res), "ошибка запуска") {
		t.Errorf("не отражён сбой запуска: %q", resultText(t, res))
	}
}

type notFoundError struct{}

func (notFoundError) Error() string { return "execx: run \"tplater-fake\": executable file not found" }
