package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/templatequery"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
)

func discoverExecute(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	c := newTrustRootCommand(invocation{})
	var b bytes.Buffer
	c.SetOut(&b)
	c.SetErr(&bytes.Buffer{})
	c.SetArgs(args)
	err := c.Execute()
	return b.Bytes(), err
}
func discoverData(t *testing.T, raw []byte) d.Result {
	t.Helper()
	r, err := resultdto.Decode(raw)
	if err != nil || r.Operation != resultdto.OperationTemplateDiscover {
		t.Fatalf("invalid discovery envelope %v %s", err, raw)
	}
	var data d.Result
	if json.Unmarshal(r.Data, &data) != nil {
		t.Fatal("bad data")
	}
	return data
}
func TestTemplateDiscoveryCLIReadOnlyPinnedFollowup(t *testing.T) {
	requireGit(t)
	home := filepath.Join(t.TempDir(), "cache")
	clone := filepath.Join(home, "repos", "examples")
	_ = os.MkdirAll(clone, 0700)
	t.Setenv(state.HomeEnv, home)
	raw := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: go-service\n  version: 1.0.0\n  description: Go service with explicit manual dependency injection\n  labels:\n    tags: [service, сервис]\n    lang: [go]\n    keywords: [service, сервис]\n    readiness: [experimental]\nengine:\n  type: gotemplate\n  root: files\n")
	if err := os.WriteFile(filepath.Join(clone, "template.manifest.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	runGitForTemplateTests(t, clone, "init", "-b", "main")
	commitAllForTemplateTests(t, clone)
	idx := state.NewIndex(time.Now())
	idx.Repos["examples"] = []state.TemplateEntry{{Name: "go-service", Version: "1.0.0", Description: "stale cached metadata", Path: ".", Ref: "main", Tags: []string{}}}
	if err := state.SaveIndex(home, idx); err != nil {
		t.Fatal(err)
	}
	before := contextReadImage(t, home)
	emptyProject := t.TempDir()
	out, err := discoverExecute(t, "template", "discover", "--task", "Создать сервис go", "--dir", emptyProject, "--language", "go", "--max-bytes", "2048", "--json")
	if err != nil {
		t.Fatal(err, string(out))
	}
	data := discoverData(t, out)
	if len(out) > 2048 || len(data.Suggestions) != 1 || data.Facts.Status != "empty" {
		t.Fatalf("invalid bounded empty Go result %+v bytes%d", data, len(out))
	}
	s := data.Suggestions[0]
	if s.SourcePin.Qualification != "local-observed" || s.SourcePin.ManifestSHA256 != d.Digest(raw) || s.Readiness != d.Experimental || len(s.NextToolCalls) != 1 {
		t.Fatal(s)
	}
	call := s.NextToolCalls[0]
	ref := call.Arguments["ref"].(string)
	commit := call.Arguments["commit"].(string)
	sha := call.Arguments["manifestSHA256"].(string)
	shown, err := discoverExecute(t, "template", "show", ref, "--commit", commit, "--manifest-sha256", sha, "--json")
	if err != nil {
		t.Fatal(err, string(shown))
	}
	env, err := resultdto.Decode(shown)
	if err != nil || env.Operation != resultdto.OperationTemplateShow {
		t.Fatal(err)
	}
	var show resultdto.TemplateShowData
	_ = json.Unmarshal(env.Data, &show)
	if show.Description != "Go service with explicit manual dependency injection" {
		t.Fatal("cache description used as source")
	}
	if _, err := discoverExecute(t, "template", "show", ref, "--commit", commit, "--manifest-sha256", "sha256:"+strings.Repeat("f", 64), "--json"); err == nil {
		t.Fatal("wrong manifest pin accepted")
	}
	if !reflect.DeepEqual(before, contextReadImage(t, home)) {
		t.Fatal("discovery/pinned show mutated cache/config/auth/state")
	}
	missing := filepath.Join(t.TempDir(), "not-created")
	t.Setenv(state.HomeEnv, missing)
	out, err = discoverExecute(t, "template", "discover", "--task", "entity", "--json")
	if err != nil || len(discoverData(t, out).Suggestions) != 0 {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("root pre-run initialized state")
	}
}
func TestTemplateDiscoveryInstalledCatalogAndFollowups(t *testing.T) {
	testfixture.RequireTrustStore(t)
	old := *graphReceipts
	*graphReceipts = t.TempDir()
	t.Cleanup(func() { *graphReceipts = old })
	f, input := graphInstalledFixture(t)
	seedDiscoveryBudgetCache(t, f.home)
	before := discoveryReadonlyImage(t, f.base)
	routeStarted := time.Now()
	out, err := f.run("template", "discover", "--task", "context review", "--source-input", input, "--project-context", "root", "--dir", f.project, "--max-bytes", "16384", "--json")
	t.Logf("installed CLI discovery elapsed=%s terminal=%v", time.Since(routeStarted), err)
	if err != nil {
		traceDiscoveryAdmissionFailure(t, f, input)
		t.Fatalf("actual installed discovery %v %s", err, out)
	}
	data := discoverData(t, out)
	if len(data.Suggestions) != 1 {
		t.Fatal("actual catalog candidate missing", data)
	}
	s := data.Suggestions[0]
	if s.SourcePin.Qualification != "owner-supplied" || len(s.Blocks) != 1 || len(s.Skills) != 1 || s.Blocks[0].Availability != "admitted-record" || s.Blocks[0].CandidateKind != d.KindContext || s.Skills[0].CandidateKind != d.KindSkill || s.Readiness != d.Unknown {
		t.Fatal("catalog join/prose boundary", s)
	}
	if len(s.NextToolCalls) != 2 {
		t.Fatal("missing actual readonly followups", s)
	}
	for _, call := range s.NextToolCalls {
		if call.Tool != "graph_exports" {
			t.Fatal("invented tool")
		}
		args := call.Arguments
		sel := args["selectors"].([]any)[0].(string)
		got, err := f.run("graph", "exports", "--dir", args["dir"].(string), "--project-context", args["projectContext"].(string), "--source-input", args["sourceInput"].(string), "--select", sel, "--expected-digest", args["expectedDigest"].(string), "--limit", "1", "--max-bytes", "4096", "--representation", args["representation"].(string), "--json")
		if err != nil {
			t.Fatalf("actual emitted followup failed %v %s", err, got)
		}
		env, err := resultdto.Decode(got)
		if err != nil || env.Operation != resultdto.OperationGraphExports {
			t.Fatal(err)
		}
	}

	// The same normal graph consumer refuses a changed locator's mismatching graph
	// digest; expectedDigest is equality data, never an admission capability.
	firstArgs := s.NextToolCalls[0].Arguments
	wrong, wrongErr := f.run("graph", "exports", "--dir", firstArgs["dir"].(string), "--project-context", firstArgs["projectContext"].(string), "--source-input", firstArgs["sourceInput"].(string), "--select", firstArgs["selectors"].([]any)[0].(string), "--expected-digest", d.Digest([]byte("different original graph")), "--limit", "1", "--max-bytes", "4096", "--representation", "page", "--json")
	if wrongErr == nil || !bytes.Contains(wrong, []byte("GRAPH_SOURCE_STALE")) {
		t.Fatalf("actual normal graph consumer accepted mismatched followup graph: %v %s", wrongErr, wrong)
	}

	// Actual held-image MCP route, not just a recording runner or tool docs.
	server, serverCtx := discoveryStartMCP(t, f)
	serverStarted := time.Now()
	phase := "initial admitted discovery"
	readFrame := func() []byte {
		raw, e := server.reader.ReadBytes('\n')
		t.Logf("actual MCP phase=%s serverElapsed=%s readError=%v ctx.Err=%v", phase, time.Since(serverStarted), e, serverCtx.Err())
		if e != nil {
			t.Fatalf("actual MCP phase=%s stdio=%v ctx.Err=%v stderr=%s", phase, e, serverCtx.Err(), server.stderr.String())
		}
		return raw
	}
	server.write(t, map[string]any{"jsonrpc": "2.0", "id": "discovery-17", "method": "tools/call", "params": map[string]any{"name": "template_discover", "arguments": map[string]any{"task": "context review", "sourceInput": input, "projectContext": "root", "dir": f.project, "maxBytes": 16384}}})
	frame := readFrame()
	var response struct {
		Result struct {
			IsError           bool            `json:"isError"`
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if len(frame) > 16384 || json.Unmarshal(frame, &response) != nil || response.Result.IsError {
		t.Fatalf("MCP %s", frame)
	}
	mcpData := discoverData(t, response.Result.StructuredContent)
	if len(mcpData.Suggestions) != 1 || mcpData.Suggestions[0].ID != s.ID {
		t.Fatal("normal CLI/MCP diverged")
	}

	phase = "long original string ID whole-frame budget"
	longID := strings.Repeat("request-", 128)
	server.write(t, map[string]any{"jsonrpc": "2.0", "id": longID, "method": "tools/call", "params": map[string]any{"name": "template_discover", "arguments": map[string]any{"task": "context review", "sourceInput": input, "projectContext": "root", "dir": f.project, "maxBytes": 4096}}})
	longFrame := readFrame()
	var bounded struct {
		ID     string `json:"id"`
		Result struct {
			IsError           bool            `json:"isError"`
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if len(longFrame) > 4096 || json.Unmarshal(longFrame, &bounded) != nil || bounded.ID != longID || bounded.Result.IsError {
		t.Fatalf("whole MCP long ID budget %d %s", len(longFrame), longFrame)
	}
	if discoverData(t, bounded.Result.StructuredContent).APIVersion != d.APIVersion {
		t.Fatal("bounded floor absent")
	}

	server.close(t)
	server, serverCtx = discoveryStartMCP(t, f)
	serverStarted = time.Now()
	phase = "simultaneous original numeric IDs and optional-data budget"
	// Two original int64 IDs share the SDK float projection. The transport must
	// retain separate original ownership keys and exact wire response values.
	callDiscovery := func(id int64, args map[string]any) {
		server.write(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "template_discover", "arguments": args}})
	}
	localArgs := map[string]any{"task": "entity", "maxBytes": 2048}
	const firstID int64 = 9007199254740992
	const secondID int64 = 9007199254740993
	callDiscovery(firstID, localArgs)
	callDiscovery(secondID, localArgs)
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		raw := readFrame()
		var exact struct {
			ID     json.RawMessage `json:"id"`
			Result struct {
				IsError           bool            `json:"isError"`
				StructuredContent json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if len(raw) > 2048 || json.Unmarshal(raw, &exact) != nil || exact.Result.IsError || seen[string(exact.ID)] {
			t.Fatalf("separate exact numeric ownership %s", raw)
		}
		seen[string(exact.ID)] = true
		if got := discoverData(t, exact.Result.StructuredContent); !got.Budget.Truncated {
			t.Fatal("many-candidate whole-frame budget did not truncate optional data", got.Budget)
		}
	}
	if !seen["9007199254740992"] || !seen["9007199254740993"] {
		t.Fatal("SDK numeric ID rounding", seen)
	}

	phase = "malformed cancellation and exact duplicate refusal"
	// Duplicate refusal must preserve the still-live original request. Source
	// admission provides actual bounded work while both frames are dispatched.
	ownedArgs := map[string]any{"task": "context review", "sourceInput": input, "projectContext": "root", "dir": f.project, "maxBytes": 16384}
	callDiscovery(firstID, ownedArgs)
	// Malformed cancellation targets the active exact ID, yet must not cancel
	// it. Both finite refusals precede a normal surviving original response.
	server.write(t, map[string]any{"jsonrpc": "1.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": firstID}})
	badDuplicate := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9007199254740993,"requestId":9007199254740992}}` + "\n")
	if _, e := server.stdin.Write(badDuplicate); e != nil {
		t.Fatal(e)
	}
	server.write(t, map[string]any{"jsonrpc": "2.0", "id": firstID, "method": "tools/call", "params": map[string]any{"name": "template_discover", "arguments": ownedArgs}})

	duplicateRefused, originalCompleted := 0, false
	for i := 0; i < 4; i++ {
		raw := readFrame()
		var v struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
			Result *struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		if len(raw) > 16384 || json.Unmarshal(raw, &v) != nil {
			t.Fatalf("duplicate frame %s", raw)
		}
		if string(v.ID) == "null" && v.Error != nil && v.Error.Code == -32600 {
			duplicateRefused++
		} else if string(v.ID) == "9007199254740992" && v.Result != nil && !v.Result.IsError {
			originalCompleted = true
		} else {
			t.Fatalf("duplicate changed original owner %s", raw)
		}
	}
	if duplicateRefused != 3 || !originalCompleted {
		t.Fatal("missing exact duplicate refusal/original result")
	}
	server.close(t)
	server, serverCtx = discoveryStartMCP(t, f)
	serverStarted = time.Now()
	phase = "valid exact numeric cancellation preserves peer"
	// Cancellation keys also use the original int64, never its float projection.
	callDiscovery(firstID, ownedArgs)
	callDiscovery(secondID, localArgs)
	server.write(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": firstID}})
	rawExact := readFrame()
	var remaining struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if len(rawExact) > 2048 || json.Unmarshal(rawExact, &remaining) != nil || string(remaining.ID) != "9007199254740993" || remaining.Result.IsError {
		t.Fatalf("cancellation crossed original numeric owner %s", rawExact)
	}
	phase = "unchanged pre-existing graph route"
	// A pre-existing graph route retains its original dispatcher/ID contract.
	server.write(t, map[string]any{"jsonrpc": "2.0", "id": "original-graph-route", "method": "tools/call", "params": map[string]any{"name": "graph_exports", "arguments": s.NextToolCalls[0].Arguments}})
	graphFrame := readFrame()
	var unchanged struct {
		ID     string `json:"id"`
		Result struct {
			IsError           bool            `json:"isError"`
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(graphFrame, &unchanged) != nil || unchanged.ID != "original-graph-route" || unchanged.Result.IsError {
		t.Fatalf("original graph route altered %s", graphFrame)
	}
	graphEnv, e := resultdto.Decode(unchanged.Result.StructuredContent)
	if e != nil || graphEnv.Operation != resultdto.OperationGraphExports {
		t.Fatal("original graph contract", e)
	}

	phase = "closed invalid arguments and mandatory floor refusals"
	for i, args := range []map[string]any{{"task": "context", "unknownAuthority": true}, {"task": 12}, {"task": "context", "maxCandidates": 1.5}, {"task": "context", "maxBytes": 2048}} {
		id := fmt.Sprintf("invalid-%d", i)
		if i == 3 {
			id = strings.Repeat("oversized-", 400)
		}
		server.write(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "template_discover", "arguments": args}})
		refused := readFrame()
		var refusal struct {
			ID    any `json:"id"`
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		ceiling := 16384
		if i == 3 {
			ceiling = 2048
		}
		if len(refused) > ceiling || json.Unmarshal(refused, &refusal) != nil || refusal.Error.Code != -32600 || refusal.Error.Message != "GRAPH_OUTPUT_BUDGET" {
			t.Fatalf("closed malformed/mandatory-floor refusal %s", refused)
		}
	}
	server.close(t)
	if !reflect.DeepEqual(before, discoveryReadonlyImage(t, f.base)) {
		t.Fatal("installed discovery changed owner/project state")
	}
	t.Logf("actual installed source catalog joins and CLI/MCP/read followups passed; CLI bytes=%d MCP frame=%d", len(out), len(frame))
}

// This failure-only observation runs the real public admission stages with the
// unchanged route deadline. It neither replaces the failed child receipt nor
// manufactures a successful source, and records ctx.Err at each actual boundary.
func traceDiscoveryAdmissionFailure(t *testing.T, f *rootB2Fixture, input string) {
	t.Helper()
	t.Setenv(state.HomeEnv, f.home)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	report := func(phase string, e error) bool {
		t.Logf("separate failure diagnostic phase=%s elapsed=%s error=%v ctx.Err=%v", phase, time.Since(start), e, ctx.Err())
		return e == nil
	}
	r, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	if !report("OpenRuntime", e) {
		return
	}
	defer r.Close()
	raw, e := os.ReadFile(input)
	if !report("read fixed original source selection", e) {
		return
	}
	sources, e := contextsource.PrepareContextSources(ctx, r, raw)
	if !report("PrepareContextSources full admission", e) {
		return
	}
	defer sources.Close()
	op, e := sources.BeginOperation(ctx, r)
	if !report("BeginOperation", e) {
		return
	}
	pins, e := op.Pins()
	if !report("Pins calculation", e) {
		return
	}
	_, e = op.Catalogs()
	if !report("Catalogs calculation", e) {
		return
	}
	_, e = op.SourceGraph()
	if !report("SourceGraph calculation", e) {
		return
	}
	for _, pin := range pins {
		_, e = op.Resolution(pin.Alias)
		if !report("Resolution calculation", e) {
			return
		}
	}
	e = op.FinalRecheck(ctx, r)
	report("FinalRecheck full closure", e)
}

// Public declared fixture metadata exercises optional-data truncation in the
// real stdio route. This setup occurs before the complete readonly state image.
func seedDiscoveryBudgetCache(t *testing.T, home string) {
	t.Helper()
	clone := filepath.Join(home, "repos", "budget-examples")
	if e := os.MkdirAll(clone, 0700); e != nil {
		t.Fatal(e)
	}
	idx := state.NewIndex(time.Now())
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("entity-%02d", i)
		folder := filepath.Join(clone, name)
		if e := os.Mkdir(folder, 0700); e != nil {
			t.Fatal(e)
		}
		description, _ := json.Marshal(strings.Repeat("entity service контекст with explicit metadata ", 40))
		raw := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: " + name + "\n  version: 1.0.0\n  description: " + string(description) + "\n  labels:\n    tags: [entity, сущность]\n    lang: [go]\n    readiness: [experimental]\nengine:\n  type: gotemplate\n  root: files\n")
		if e := os.WriteFile(filepath.Join(folder, "template.manifest.yaml"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		idx.Repos["budget-examples"] = append(idx.Repos["budget-examples"], state.TemplateEntry{Name: name, Version: "1.0.0", Path: name, Ref: "main", Tags: []string{}})
	}
	runGitForTemplateTests(t, clone, "init", "-b", "main")
	commitAllForTemplateTests(t, clone)
	if e := state.SaveIndex(home, idx); e != nil {
		t.Fatal(e)
	}
}

// The same existing60s finite stdio lifetime, exposed to this test's receipts.
// Independent protocol groups use fresh normal servers instead of extending it.
func discoveryStartMCP(t *testing.T, f *rootB2Fixture) (*rootB2MCP, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	child := f.command(ctx, "mcp-server")
	s := &rootB2MCP{child: child, cancel: cancel}
	var e error
	s.stdin, e = child.StdinPipe()
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	stdout, e := child.StdoutPipe()
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	s.stdout = stdout
	s.reader = bufio.NewReader(stdout)
	child.Stderr = &s.stderr
	if e = child.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if !s.closed {
			s.stdin.Close()
			cancel()
			_ = child.Wait()
		}
	})
	s.write(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "public-discovery-fixture", "version": "1"}}})
	s.read(t)
	s.write(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return s, ctx
}

// Opt-in diagnosis of the genuine installed public owner, not a replacement
// acceptance suite. Profile only the unchanged15s admission window; fixture
// creation/build/New are excluded from CPU/trace observations.
func TestTemplateDiscoveryAdmissionProfile(t *testing.T) {
	dir := os.Getenv("TPLAITER_DISCOVERY_ADMISSION_PROFILE_DIR")
	if dir == "" {
		t.Skip("finite admission profiling is opt-in")
	}
	testfixture.RequireTrustStore(t)
	old := *graphReceipts
	*graphReceipts = t.TempDir()
	t.Cleanup(func() { *graphReceipts = old })
	f, input := graphInstalledFixture(t)
	t.Setenv(state.HomeEnv, f.home)
	before := rootB2Image(t, f.project, f.home, f.install)
	cpu, e := os.Create(filepath.Join(dir, "admission.cpu.pprof"))
	if e != nil {
		t.Fatal(e)
	}
	defer cpu.Close()
	timeline, e := os.Create(filepath.Join(dir, "admission.trace"))
	if e != nil {
		t.Fatal(e)
	}
	defer timeline.Close()
	if e = pprof.StartCPUProfile(cpu); e != nil {
		t.Fatal(e)
	}
	if e = trace.Start(timeline); e != nil {
		pprof.StopCPUProfile()
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	start := time.Now()
	type phaseReceipt struct {
		Phase          string  `json:"phase"`
		ElapsedSeconds float64 `json:"elapsedSeconds"`
		Error          string  `json:"error"`
		ContextError   string  `json:"contextError"`
	}
	phases := []phaseReceipt{}
	record := func(phase string, err error) {
		p := phaseReceipt{Phase: phase, ElapsedSeconds: time.Since(start).Seconds()}
		if err != nil {
			p.Error = err.Error()
		}
		if ctx.Err() != nil {
			p.ContextError = ctx.Err().Error()
		}
		phases = append(phases, p)
		t.Logf("profile phase=%s elapsed=%s err=%v ctx.Err=%v", phase, time.Since(start), err, ctx.Err())
		trace.Log(ctx, "phase", phase)
	}
	var r *trustload.Runtime
	pprof.Do(ctx, pprof.Labels("phase", "OpenRuntime"), func(ctx context.Context) {
		r, e = trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	})
	record("OpenRuntime", e)
	var sources *contextsource.PreparedContextSources
	if e == nil {
		raw, readError := os.ReadFile(input)
		e = readError
		if e == nil {
			pprof.Do(ctx, pprof.Labels("phase", "PrepareContextSources"), func(ctx context.Context) { sources, e = contextsource.PrepareContextSources(ctx, r, raw) })
		}
		record("PrepareContextSources full admission", e)
	}
	elapsed := time.Since(start).Seconds()
	trace.Stop()
	pprof.StopCPUProfile()
	cancel()
	if sources != nil {
		sources.Close()
	}
	if r != nil {
		r.Close()
	}
	receipt := map[string]any{"base": "7821b57349ccf19e11f4b9d714060d8fe2f7c4a5", "deadlineSeconds": 15, "elapsedSeconds": elapsed, "phases": phases, "qualification": "Instrumented independent genuine admission observation; fixture creation/New excluded, no installed discovery acceptance claim; CPU samples are not exact recheck counts", "publicRecheckObserver": "none accessible; trustload test observers are unexported and were not forged"}
	raw, _ := json.MarshalIndent(receipt, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "phase-receipt.json"), append(raw, byte(10)), 0600); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, rootB2Image(t, f.project, f.home, f.install)) {
		t.Fatal("profiled admission changed original owner/project state")
	}
}

// This fixture proves presentation only; it supplies no admitted owner or authority.
func TestTemplateDiscoverySerializedFrameBudget(t *testing.T) {
	pin := d.SourcePin{Qualification: "local-observed", Repo: "examples", Path: "entity", Commit: strings.Repeat("a", 40), ManifestSHA256: d.Digest([]byte("manifest"))}
	candidate, err := d.Identify(d.Candidate{SourcePin: pin, MetadataSHA256: pin.ManifestSHA256, Name: "entity", Version: "1", Description: "Entity declaration with manual dependency injection", Labels: map[string][]string{"tags": {"entity"}, "lang": {"go"}}, CandidateKind: d.KindTemplate, Readiness: d.Experimental, Blocks: []d.Reference{}, Skills: []d.Reference{}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := d.Rank(d.Query{Task: "entity"}, []d.Candidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	ref := d.Reference{ID: "account-controller", SourcePin: pin, CandidateKind: d.KindContext, Readiness: d.Unknown, DeclarationStatus: "metadata-declared", Availability: "admitted-record", Provenance: &d.Provenance{CatalogSource: "catalog", Provider: "fixture", ContractSHA256: d.Digest([]byte("contract")), ExportID: "account-controller", Domain: "context", ContentSHA256: d.Digest([]byte("body"))}}
	data.Suggestions[0].Blocks = []d.Reference{ref}
	data.Suggestions[0].NextToolCalls = []d.ReadOnlyCall{{Tool: "graph_exports", Arguments: map[string]any{"dir": "/observed/project", "projectContext": "project", "sourceInput": "{pinned selection}", "expectedDigest": d.Digest([]byte("resolved original singleton graph")), "selectors": []string{"account-controller"}, "limit": 1, "maxBytes": 4096, "representation": "page"}}}
	for _, ceiling := range []int{8192, 2048} {
		t.Run(fmt.Sprint(ceiling), func(t *testing.T) {
			command := newTemplateDiscoverCmd()
			var out bytes.Buffer
			command.SetOut(&out)
			command.SetContext(context.Background())
			layout := resultwire.DiscoveryFrameLayout{APIVersion: resultwire.DiscoveryFrameVersion, ID: json.RawMessage("9007199254740993"), Ceiling: ceiling}
			err := emitDiscoveryOwned(context.Background(), command, data, ceiling, nil, &layout)
			if err != nil {
				var typed *resultdto.LifecycleError
				if !errors.As(err, &typed) || typed.Code != "DISCOVERY_OUTPUT_BUDGET" {
					t.Fatal(err)
				}
				if ceiling == 8192 {
					t.Fatal("representative frame unexpectedly refused", err)
				}
				return
			}
			env, e := resultdto.Decode(out.Bytes())
			if e != nil {
				t.Fatal(e)
			}
			frame, e := resultwire.Frame(layout.RequestID(), resultwire.Structured(env, false))
			if e != nil || len(frame) > ceiling {
				t.Fatalf("whole frame %d ceiling%d: %v", len(frame), ceiling, e)
			}
			var response struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(frame, &response) != nil || string(response.ID) != "9007199254740993" {
				t.Fatal("original numeric ID lost", string(frame))
			}
			actual := discoverData(t, out.Bytes())
			if ceiling == 8192 && (len(actual.Suggestions) != 1 || len(actual.Suggestions[0].Blocks) != 1 || len(actual.Suggestions[0].NextToolCalls) != 1 || actual.Suggestions[0].Description != candidate.Description) {
				t.Fatal("representative grounded description/reference/call omitted", actual)
			}
		})
	}
	command := newTemplateDiscoverCmd()
	command.SetOut(&bytes.Buffer{})
	command.SetContext(context.Background())
	hugeID, _ := json.Marshal(strings.Repeat("x", 10000))
	layout := resultwire.DiscoveryFrameLayout{APIVersion: resultwire.DiscoveryFrameVersion, ID: hugeID, Ceiling: 2048}
	err = emitDiscoveryOwned(context.Background(), command, data, 2048, nil, &layout)
	var typed *resultdto.LifecycleError
	if !errors.As(err, &typed) || typed.Code != "DISCOVERY_OUTPUT_BUDGET" {
		t.Fatal("oversized mandatory ID floor was not typed output-budget refusal", err)
	}
}

// The genuine fixture's entire state is covered, including original source,
// installation, local cache/config and binary. Credential-shaped paths use only
// stat metadata; their contents are never loaded by this observer.
func discoveryReadonlyImage(t *testing.T, root string) map[string]string {
	t.Helper()
	image := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		value := fmt.Sprintf("%s:%d", info.Mode(), info.Size())
		name := strings.ToLower(entry.Name())
		credential := strings.Contains(name, "credential") || strings.Contains(name, "secret") || strings.Contains(name, "private-key") || name == "auth.json" || name == "oauth.json"
		if credential {
			value += fmt.Sprintf(":mtime=%d", info.ModTime().UnixNano())
		} else if info.Mode().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			value += ":" + d.Digest(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(path)
			if e != nil {
				return e
			}
			value += ":" + target
		}
		image[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

// One actual admitted result is measured independently of the installed matrix.
func TestTemplateDiscoveryAuthenticFrameFloor(t *testing.T) {
	dir := os.Getenv("TPLAITER_DISCOVERY_FRAME_FLOOR_DIR")
	if dir == "" {
		t.Skip("bounded authentic frame-floor diagnosis is opt-in")
	}
	testfixture.RequireTrustStore(t)
	old := *graphReceipts
	*graphReceipts = t.TempDir()
	t.Cleanup(func() { *graphReceipts = old })
	f, input := graphInstalledFixture(t)
	t.Setenv(state.HomeEnv, f.home)
	before := discoveryReadonlyImage(t, f.base)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runtime, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: f.in.Selection, ProjectKey: "root", Clock: f.in.Clock})
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	raw, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := templatequery.Admit(ctx, runtime, raw, input, "root", d.Query{Task: "context review", Facts: templatequery.ObserveProject(f.project), MaxBytes: 16384})
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	originalID, _ := json.Marshal(strings.Repeat("request-", 128))
	layout := resultwire.DiscoveryFrameLayout{APIVersion: resultwire.DiscoveryFrameVersion, ID: originalID, Ceiling: 4096}
	rows := []map[string]any{}
	for _, budget := range []int{16384, 8192, 4096, 3072, 2560, 2048, 1792, 1536, 1280, 1024, 768, 512} {
		data, err := owner.Fit(ctx, budget)
		row := map[string]any{"dataBudget": budget}
		if err != nil {
			row["error"] = err.Error()
			rows = append(rows, row)
			continue
		}
		env := newResult(resultdto.OperationTemplateDiscover)
		if err = env.SetData(data); err != nil {
			t.Fatal(err)
		}
		envelope, err := resultdto.MarshalCanonical(env)
		if err != nil {
			t.Fatal(err)
		}
		structured := resultwire.Structured(env, false)
		frame, err := resultwire.Frame(layout.RequestID(), structured)
		if err != nil {
			t.Fatal(err)
		}
		row["canonicalEnvelopeBytes"] = len(envelope)
		row["wholeFrameBytes"] = len(frame)
		row["result"] = data
		rows = append(rows, row)
	}
	command := newTemplateDiscoverCmd()
	var emitted bytes.Buffer
	command.SetOut(&emitted)
	command.SetContext(ctx)
	emissionError := emitDiscoveryOwned(ctx, command, owner.Result(), 4096, owner, &layout)
	outcome := "success"
	if emissionError != nil {
		var typed *resultdto.LifecycleError
		if !errors.As(emissionError, &typed) || typed.Code != "DISCOVERY_OUTPUT_BUDGET" {
			t.Fatal(emissionError)
		}
		outcome = typed.Code
	}

	if emissionError != nil {
		t.Fatalf("authentic useful4096 frame must fit after optional record trimming: %v", emissionError)
	}
	actualEnvelope, decodeError := resultdto.Decode(emitted.Bytes())
	if decodeError != nil {
		t.Fatal(decodeError)
	}
	actualFrame, frameError := resultwire.Frame(layout.RequestID(), resultwire.Structured(actualEnvelope, false))
	if frameError != nil || len(actualFrame) > 4096 {
		t.Fatalf("authentic whole frame %d exceeds4096: %v", len(actualFrame), frameError)
	}
	useful := discoverData(t, emitted.Bytes())
	if len(useful.Suggestions) != 1 || len(useful.Suggestions[0].Blocks)+len(useful.Suggestions[0].Skills) == 0 || len(useful.Suggestions[0].NextToolCalls) == 0 || !useful.Budget.Truncated {
		t.Fatal("authentic grounded reference/readcall floor lost", useful)
	}
	if useful.Suggestions[0].ID != owner.Result().Suggestions[0].ID || useful.Suggestions[0].SourcePin != owner.Result().Suggestions[0].SourcePin {
		t.Fatal("immutable original candidate identity changed")
	}
	var originalResponse struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(actualFrame, &originalResponse) != nil || !bytes.Equal(originalResponse.ID, originalID) {
		t.Fatal("authentic exact originalID changed")
	}
	packet := map[string]any{"rawOriginalID": json.RawMessage(originalID), "originalIDBytes": len(originalID), "ceiling": 4096, "normalOwnerEmission": outcome, "actualWholeFrameBytes": len(actualFrame), "fits": rows, "qualification": "Actual normal admitted owner result and owner Fit; exact resultwire Structured/Frame production serialization. These are equality/size observations, not new authority or full installed runtime acceptance."}
	bytes, e := json.MarshalIndent(packet, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "floor-receipt.json"), append(bytes, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, discoveryReadonlyImage(t, f.base)) {
		t.Fatal("authentic size observation mutated owner state")
	}
}
