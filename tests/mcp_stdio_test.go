package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The stdio contract suite drives a real MCP server process over stdin/stdout
// JSON-RPC, exactly like an agent client does, against the tplaiter binary
// built by TestMain and an offline fixture template repository.
//
// Server under test. The production entry point `tplaiter mcp-server`
// requires an installed trust registration (U02); until that fixture exists
// the suite runs the same tool registry through the stdio harness
// (internal/mcpsrv/cmd/stdioharness), which executes the same tplaiter binary
// with the same sanitized child environment, process-group cancellation and
// output bounds, but without the installed held-stage image. The unprovisioned
// `tplaiter mcp-server` is asserted to fail closed with TRUST_ANCHOR_MISSING.
// Set TPLAITER_E2E_MCP_COMMAND to a space-separated command (for example an
// installed binary with its trust state) to run the whole suite against it.
//
// Pending tools. testdata/mcp/pending_tools.txt lists the tools whose success
// path lands in a later work package (trust registration, live lifecycle,
// trusted actions). The suite still calls each of them and requires a typed
// result/v1 failure envelope; once a tool is removed from the file its call
// must succeed.

const (
	toolsGoldenFile  = "testdata/mcp/tools.schema.golden.json"
	pendingToolsFile = "testdata/mcp/pending_tools.txt"
)

// mcpClient is a minimal JSON-RPC 2.0 client over a child's stdio.
type mcpClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr *bytes.Buffer
	nextID atomic.Int64

	mu      sync.Mutex
	waiters map[int64]chan rpcMessage
	closed  chan struct{}
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// startMCP starts argv with env and completes the initialize handshake.
func startMCP(t *testing.T, env []string, argv ...string) *mcpClient {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = t.TempDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &mcpClient{t: t, cmd: cmd, stdin: stdin, stderr: &bytes.Buffer{}, waiters: map[int64]chan rpcMessage{}, closed: make(chan struct{})}
	cmd.Stderr = c.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %v: %v", argv, err)
	}
	go c.readLoop(stdout)
	t.Cleanup(c.shutdown)
	return c
}

func (c *mcpClient) readLoop(stdout io.Reader) {
	defer close(c.closed)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	for scanner.Scan() {
		var msg rpcMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil || msg.ID == nil {
			continue // notifications and log noise are not responses
		}
		c.mu.Lock()
		ch := c.waiters[*msg.ID]
		delete(c.waiters, *msg.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

func (c *mcpClient) shutdown() {
	_ = c.stdin.Close()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

func (c *mcpClient) send(v any) {
	c.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.stdin.Write(append(raw, '\n')); err != nil {
		c.t.Fatalf("write to MCP server: %v (stderr: %s)", err, c.stderr.String())
	}
}

// start sends a request and returns its id and the channel of its response.
func (c *mcpClient) start(method string, params any) (int64, chan rpcMessage) {
	id := c.nextID.Add(1)
	ch := make(chan rpcMessage, 1)
	c.mu.Lock()
	c.waiters[id] = ch
	c.mu.Unlock()
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	c.send(msg)
	return id, ch
}

func (c *mcpClient) await(ch chan rpcMessage, method string, timeout time.Duration) rpcMessage {
	c.t.Helper()
	select {
	case msg := <-ch:
		if msg.Error != nil {
			c.t.Fatalf("%s: JSON-RPC error %d %s", method, msg.Error.Code, msg.Error.Message)
		}
		return msg
	case <-c.closed:
		c.t.Fatalf("%s: MCP server closed stdout (stderr: %s)", method, c.stderr.String())
	case <-time.After(timeout):
		c.t.Fatalf("%s: no response within %v (stderr: %s)", method, timeout, c.stderr.String())
	}
	return rpcMessage{}
}

func (c *mcpClient) call(method string, params any) json.RawMessage {
	c.t.Helper()
	_, ch := c.start(method, params)
	return c.await(ch, method, 5*time.Minute).Result
}

func (c *mcpClient) initialize() map[string]any {
	c.t.Helper()
	raw := c.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "tplaiter-stdio-suite", "version": "1"},
	})
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		c.t.Fatal(err)
	}
	return result
}

// toolResult is a tools/call result.
type toolResult struct {
	IsError           bool             `json:"isError"`
	Content           []map[string]any `json:"content"`
	StructuredContent map[string]any   `json:"structuredContent"`
}

func (c *mcpClient) callTool(name string, args map[string]any) toolResult {
	c.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	raw := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	var res toolResult
	if err := json.Unmarshal(raw, &res); err != nil {
		c.t.Fatalf("tools/call %s: %v\n%s", name, err, raw)
	}
	return res
}

// envelopeRequiredKeys are the result/v1 top-level keys (schema/result.v1.schema.json).
var envelopeRequiredKeys = []string{"apiVersion", "kind", "operation", "status", "project", "transactionId", "summary", "changes", "diagnostics", "artifacts", "meta"}

// requireEnvelope checks the structural result/v1 contract of a tool result
// and returns its operation, status and diagnostic codes. (The full schema is
// enforced server-side: mcp-go validates structured content against each
// tool's outputSchema, and internal/mcpsrv tests compile every schema.)
func requireEnvelope(t *testing.T, tool string, res toolResult) (op, status string, codes []string) {
	t.Helper()
	env := res.StructuredContent
	if env == nil {
		t.Fatalf("%s: no structuredContent: %+v", tool, res.Content)
	}
	for _, key := range envelopeRequiredKeys {
		if _, ok := env[key]; !ok {
			t.Fatalf("%s: envelope lacks %q: %v", tool, key, env)
		}
	}
	if env["apiVersion"] != "tplaiter.dev/result/v1" {
		t.Fatalf("%s: apiVersion=%v", tool, env["apiVersion"])
	}
	op, _ = env["operation"].(string)
	status, _ = env["status"].(string)
	diagnostics, _ := env["diagnostics"].([]any)
	for _, d := range diagnostics {
		if m, ok := d.(map[string]any); ok {
			code, _ := m["code"].(string)
			codes = append(codes, code)
		}
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: no text summary", tool)
	}
	text, _ := res.Content[0]["text"].(string)
	if !strings.HasPrefix(text, op+": "+status) || strings.Count(text, "\n") >= 12 {
		t.Fatalf("%s: summary %q is not the bounded summary of %s/%s", tool, text, op, status)
	}
	return op, status, codes
}

func readPending(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(pendingToolsFile)
	if err != nil {
		t.Fatal(err)
	}
	pending := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, reason, _ := strings.Cut(line, " ")
		pending[name] = strings.TrimSpace(reason)
	}
	return pending
}

// buildHarness builds the stdio harness from the root module.
func buildHarness(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "stdioharness")
	cmd := exec.Command("go", "build", "-o", out, "./internal/mcpsrv/cmd/stdioharness")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stdio harness: %v\n%s", err, b)
	}
	return out
}

// serverEnv is the environment of the MCP server process: an isolated
// tplaiter home, HOME and XDG roots; nothing from the developer's machine.
func serverEnv(home string) []string {
	return []string{
		"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "NO_COLOR=1",
		"HOME=" + home, "TPLAITER_HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "xdg-config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "xdg-cache"),
		"XDG_DATA_HOME=" + filepath.Join(home, "xdg-data"),
		"XDG_STATE_HOME=" + filepath.Join(home, "xdg-state"),
		"TMPDIR=" + os.TempDir(),
		"GOPROXY=off", "GIT_CONFIG_NOSYSTEM=1",
	}
}

func serverCommand(harness string, extra ...string) []string {
	if custom := strings.TrimSpace(os.Getenv("TPLAITER_E2E_MCP_COMMAND")); custom != "" {
		return strings.Fields(custom)
	}
	return append([]string{harness, "-exe", binPath, "-version", buildVersion}, extra...)
}

// writeStaticProject writes a generated-project fixture (marker plus manifest
// snapshot) that read-only project tools can inspect without the live
// lifecycle, which lands later.
func writeStaticProject(t *testing.T, manifestPath string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(root, ".tplaiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := "apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: stdio-suite-demo\n" +
		"template:\n  repo: fixture\n  name: single-basic\n  version: v0.1.0\n" +
		"project:\n  name: Demo\n  slug: demo\n" +
		"settings:\n  database: none\n"
	if err := os.WriteFile(filepath.Join(root, ".tplaiter", "project.yaml"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot := mustReadFile(t, manifestPath)
	if err := os.WriteFile(filepath.Join(root, ".tplaiter", "manifest.snapshot.yaml"), []byte(snapshot), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestMCPStdioUnprovisionedServerFailsClosed(t *testing.T) {
	home := newHome(t)
	cmd := exec.Command(binPath, "mcp-server")
	cmd.Env = serverEnv(home)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 5 {
		t.Fatalf("unprovisioned mcp-server: err=%v stdout=%q stderr=%q, want exit 5 (trust)", err, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "TRUST_ANCHOR_MISSING") {
		t.Fatalf("unprovisioned mcp-server must refuse before serving: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestMCPStdioContract is the full contract suite: initialize, tools/list
// against the golden schemas, resources, and one tools/call for every tool.
func TestMCPStdioContract(t *testing.T) {
	requireGit(t)
	harness := buildHarness(t)
	home := newHome(t)
	// The static project pins v0.1.0, which the fixture origin must carry as a
	// tag for stats to render the baseline.
	origin := buildSingleOrigin(t, filepath.Join(fixturesDir(t), "single-basic"), "v0.1.0", "v1.0.0")
	project := writeStaticProject(t, filepath.Join(origin, "template.manifest.yaml"))
	workdir := t.TempDir()

	c := startMCP(t, serverEnv(home), serverCommand(harness)...)
	initResult := c.initialize()
	if info, _ := initResult["serverInfo"].(map[string]any); info["name"] != "tplaiter" {
		t.Fatalf("initialize serverInfo=%v", initResult["serverInfo"])
	}
	if caps, _ := initResult["capabilities"].(map[string]any); caps["tools"] == nil || caps["resources"] == nil {
		t.Fatalf("initialize capabilities=%v", initResult["capabilities"])
	}

	t.Run("tools/list golden", func(t *testing.T) { checkToolsGolden(t, c) })

	pending := readPending(t)
	calls := []struct {
		tool string
		args map[string]any
		op   string
	}{
		{"repo_add", map[string]any{"alias": "fixture", "url": "file://" + origin}, "repo.add"},
		{"repo_list", nil, "repo.list"},
		{"repo_update", map[string]any{"alias": "fixture"}, "repo.update"},
		{"template_list", nil, "template.list"},
		{"template_show", map[string]any{"ref": "single-basic"}, "template.show"},
		{"projects_list", nil, "projects.list"},
		{"doctor", map[string]any{"dir": project}, "doctor.check"},
		{"settings_list", map[string]any{"dir": project}, "settings.show"},
		{"gen_list", map[string]any{"dir": project}, "gen.list"},
		{"update", map[string]any{"dir": project, "check": true}, "update.check"},
		{"stats", map[string]any{"dir": project}, "project.stats"},
		{"lint_template", map[string]any{"path": origin}, "template.lint"},
		{"init_template", map[string]any{"name": "fresh", "dir": filepath.Join(workdir, "fresh")}, "template.init"},
		{"trust_inspect", nil, "trust.inspect"},
		{"project_new", map[string]any{"ref": "single-basic", "name": "created", "dir": workdir, "defaults": true, "noHooks": true, "noDepsCheck": true, "noEnvSetup": true}, "project.new"},
		{"run", map[string]any{"dir": project, "command": "test"}, "project.run"},
		{"ai_gen", map[string]any{"dir": project}, "ai.gen"},
		{"settings_set", map[string]any{"dir": project, "values": map[string]any{"database": "postgres"}}, "settings.set"},
		{"gen", map[string]any{"dir": project, "kind": "crud", "name": "Ride", "noBuild": true}, "gen.run"},
		{"gen_batch", map[string]any{"dir": project, "operations": []any{map[string]any{"kind": "crud", "name": "Ride"}}, "noBuild": true}, "gen.batch"},
		{"workspace_add_service", map[string]any{"dir": project, "name": "billing"}, "workspace.add-service"},
		{"env_setup", map[string]any{"dir": project, "yes": true}, "env.setup"},
		{"repo_remove", map[string]any{"alias": "fixture"}, "repo.remove"},
	}
	called := map[string]bool{}
	for _, tc := range calls {
		called[tc.tool] = true
		t.Run("tools/call "+tc.tool, func(t *testing.T) {
			res := c.callTool(tc.tool, tc.args)
			op, status, codes := requireEnvelope(t, tc.tool, res)
			if op != tc.op {
				t.Fatalf("%s: operation=%s, want %s", tc.tool, op, tc.op)
			}
			if reason, isPending := pending[tc.tool]; isPending {
				// The backend lands later: the call must fail closed with a
				// typed diagnostic, never with free text.
				if !res.IsError || (status != "blocked" && status != "failed") || len(codes) == 0 {
					t.Fatalf("%s (pending: %s): isError=%v status=%s codes=%v", tc.tool, reason, res.IsError, status, codes)
				}
				for _, code := range codes {
					if code == "MCP_CONTRACT_INVALID" || code == "MCP_UNAVAILABLE" || code == "MCP_TIMEOUT" {
						t.Fatalf("%s (pending): transport failure %s instead of a typed refusal", tc.tool, code)
					}
				}
				t.Logf("%s pending (%s): %s %v", tc.tool, reason, status, codes)
				return
			}
			if res.IsError || (status != "ok" && status != "changes") {
				t.Fatalf("%s: isError=%v status=%s codes=%v", tc.tool, res.IsError, status, codes)
			}
		})
	}
	t.Run("every tool called", func(t *testing.T) {
		for _, name := range listToolNames(t, c) {
			if !called[name] {
				t.Errorf("tool %s is registered but the suite does not call it", name)
			}
		}
		for name := range pending {
			if !called[name] {
				t.Errorf("pending_tools.txt lists unknown tool %s", name)
			}
		}
	})

	t.Run("resources", func(t *testing.T) {
		raw := c.call("resources/list", map[string]any{})
		if !bytes.Contains(raw, []byte(`"tplaiter://config"`)) {
			t.Fatalf("resources/list: %s", raw)
		}
		raw = c.call("resources/templates/list", map[string]any{})
		if !bytes.Contains(raw, []byte(`tplaiter://project/{dir}`)) {
			t.Fatalf("resources/templates/list: %s", raw)
		}
		raw = c.call("resources/read", map[string]any{"uri": "tplaiter://config"})
		if !bytes.Contains(raw, []byte(`"contents"`)) {
			t.Fatalf("resources/read config: %s", raw)
		}
		raw = c.call("resources/read", map[string]any{"uri": "tplaiter://project/" + strings.ReplaceAll(url.PathEscape(project), "/", "%2F")})
		if !bytes.Contains(raw, []byte("stdio-suite-demo")) {
			t.Fatalf("resources/read project: %s", raw)
		}
	})
}

func listToolNames(t *testing.T, c *mcpClient) []string {
	t.Helper()
	var list struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(c.call("tools/list", map[string]any{}), &list); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		name, _ := tool["name"].(string)
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkToolsGolden compares name, description, annotations, inputSchema and
// outputSchema of every tool with the golden file. Regenerate deliberately:
//
//	TPLAITER_UPDATE_GOLDEN=1 go test -run TestMCPStdioContract ./...
func checkToolsGolden(t *testing.T, c *mcpClient) {
	t.Helper()
	var list struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(c.call("tools/list", map[string]any{}), &list); err != nil {
		t.Fatal(err)
	}
	sort.Slice(list.Tools, func(i, j int) bool {
		return fmt.Sprint(list.Tools[i]["name"]) < fmt.Sprint(list.Tools[j]["name"])
	})
	for _, tool := range list.Tools {
		if tool["outputSchema"] == nil {
			t.Errorf("tool %v has no outputSchema", tool["name"])
		}
	}
	var got bytes.Buffer
	enc := json.NewEncoder(&got)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(list.Tools); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TPLAITER_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(toolsGoldenFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(toolsGoldenFile, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(toolsGoldenFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("tools/list differs from %s; review and regenerate with TPLAITER_UPDATE_GOLDEN=1", toolsGoldenFile)
	}
}

// hangingGitServer accepts HTTP connections and never answers, so that a
// `git clone` started by repo_add blocks inside git-remote-http (a
// grandchild of the tplaiter child). It reports how many connections are
// open, which proves whether the process group was torn down.
type hangingGitServer struct {
	listener net.Listener
	open     atomic.Int64
	seen     atomic.Int64
	release  chan struct{}
}

func newHangingGitServer(t *testing.T) *hangingGitServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &hangingGitServer{listener: l, release: make(chan struct{})}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.seen.Add(1)
			s.open.Add(1)
			defer s.open.Add(-1)
			select {
			case <-r.Context().Done(): // the client went away
			case <-s.release:
			}
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { close(s.release); _ = srv.Close() })
	return s
}

func (s *hangingGitServer) url(token string) string {
	return "http://" + s.listener.Addr().String() + "/" + token + ".git"
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireNoProcess fails when any process command line still contains
// token; it is skipped where ps is unavailable.
func requireNoProcess(t *testing.T, token string) {
	t.Helper()
	if _, err := exec.LookPath("ps"); err != nil {
		t.Logf("ps not available on %s; relying on the connection check", runtime.GOOS)
		return
	}
	waitFor(t, "no process mentioning "+token, 15*time.Second, func() bool {
		out, err := exec.Command("ps", "-A", "-o", "command=").Output()
		return err == nil && !bytes.Contains(out, []byte(token))
	})
}

// TestMCPStdioTimeoutVersusCancel proves over real stdio that a tool
// deadline yields MCP_TIMEOUT, a client notifications/cancelled yields a
// stopped call (MCP_CANCELLED when a response is sent), and in both cases
// the child, its git grandchildren and their network connection are gone.
func TestMCPStdioTimeoutVersusCancel(t *testing.T) {
	requireGit(t)
	if os.Getenv("TPLAITER_E2E_MCP_COMMAND") != "" {
		t.Skip("limits are harness flags; the custom server keeps production limits")
	}
	harness := buildHarness(t)
	git := newHangingGitServer(t)

	t.Run("timeout", func(t *testing.T) {
		home := newHome(t)
		c := startMCP(t, serverEnv(home), serverCommand(harness, "-timeout", "2s", "-grace", "500ms")...)
		c.initialize()
		token := fmt.Sprintf("tplaiter-timeout-%d", time.Now().UnixNano())
		start := time.Now()
		res := c.callTool("repo_add", map[string]any{"alias": "hang", "url": git.url(token)})
		_, status, codes := requireEnvelope(t, "repo_add", res)
		if !res.IsError || status != "failed" || len(codes) != 1 || codes[0] != "MCP_TIMEOUT" {
			t.Fatalf("status=%s codes=%v (seen %d requests), want MCP_TIMEOUT", status, codes, git.seen.Load())
		}
		if elapsed := time.Since(start); elapsed < 2*time.Second {
			t.Fatalf("timed out after %v, before the 2s deadline", elapsed)
		}
		diag := res.StructuredContent["diagnostics"].([]any)[0].(map[string]any)
		if ms, _ := diag["details"].(map[string]any)["durationMs"].(float64); ms < 2000 {
			t.Fatalf("durationMs=%v", diag["details"])
		}
		waitFor(t, "git connection closed after timeout", 15*time.Second, func() bool { return git.open.Load() == 0 })
		requireNoProcess(t, token)
	})

	t.Run("cancel", func(t *testing.T) {
		home := newHome(t)
		c := startMCP(t, serverEnv(home), serverCommand(harness, "-timeout", "5m", "-grace", "500ms")...)
		c.initialize()
		token := fmt.Sprintf("tplaiter-cancel-%d", time.Now().UnixNano())
		before := git.seen.Load()
		id, ch := c.start("tools/call", map[string]any{"name": "repo_add", "arguments": map[string]any{"alias": "hang", "url": git.url(token)}})
		waitFor(t, "git to reach the hanging server", time.Minute, func() bool { return git.seen.Load() > before })
		cancelledAt := time.Now()
		c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "suite"}})
		waitFor(t, "git connection closed after cancel", 15*time.Second, func() bool { return git.open.Load() == 0 })
		requireNoProcess(t, token)
		if elapsed := time.Since(cancelledAt); elapsed > 15*time.Second {
			t.Fatalf("cancellation took %v", elapsed)
		}
		// A server may omit the response to a cancelled request; when it
		// sends one, it must name the cancellation, not a timeout.
		select {
		case msg := <-ch:
			var res toolResult
			if msg.Error == nil && json.Unmarshal(msg.Result, &res) == nil && res.StructuredContent != nil {
				_, _, codes := requireEnvelope(t, "repo_add", res)
				if len(codes) != 1 || codes[0] != "MCP_CANCELLED" {
					t.Fatalf("cancelled call answered with %v", codes)
				}
			}
		case <-time.After(2 * time.Second):
		}
		// The server keeps serving after a cancellation.
		c.call("ping", map[string]any{})
	})
}

// TestMCPStdioOutputLimit: a child whose stdout exceeds the transport bound
// (1 MiB) is stopped and reported as MCP_OUTPUT_LIMIT, and the server keeps
// serving. The oversized output is a catalog entry whose description is
// larger than the bound.
func TestMCPStdioOutputLimit(t *testing.T) {
	requireGit(t)
	harness := buildHarness(t)
	home := newHome(t)
	src := filepath.Join(t.TempDir(), "huge")
	copyTree(t, filepath.Join(fixturesDir(t), "single-basic"), src)
	manifestPath := filepath.Join(src, "template.manifest.yaml")
	manifest := mustReadFile(t, manifestPath)
	huge := strings.Repeat("x", 1<<20+4096)
	manifest = strings.Replace(manifest, "description: \"Engine test fixture: select+nested toggle, multiselect, file rules.\"", "description: \""+huge+"\"", 1)
	if !strings.Contains(manifest, huge) {
		t.Fatal("fixture description not replaced")
	}
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	origin := initGitOrigin(t, src, "v1.0.0")
	c := startMCP(t, serverEnv(home), serverCommand(harness)...)
	c.initialize()
	res := c.callTool("repo_add", map[string]any{"alias": "huge", "url": "file://" + origin})
	if _, status, codes := requireEnvelope(t, "repo_add", res); status != "ok" {
		// repo add prints the repository list, which does not include
		// descriptions, so it stays within the bound.
		t.Fatalf("repo_add: %s %v", status, codes)
	}
	res = c.callTool("template_list", nil)
	_, status, codes := requireEnvelope(t, "template_list", res)
	if !res.IsError || status != "failed" || len(codes) != 1 || codes[0] != "MCP_OUTPUT_LIMIT" {
		t.Fatalf("template_list: isError=%v %s %v, want MCP_OUTPUT_LIMIT", res.IsError, status, codes)
	}
	c.call("ping", map[string]any{})
}
