package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	for name, op := range map[string]resultdto.Operation{"graph_source": resultdto.OperationGraphSource, "dependency_graph": resultdto.OperationGraphSource, "graph_exports": resultdto.OperationGraphExports, "graph_ast": resultdto.OperationGraphAST, "graph_stats": resultdto.OperationGraphStats} {
		toolOperations[name] = []resultdto.Operation{op}
	}
}
func TestGraphDomainDescriptorsAndOriginalInventory(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	before := s.MCP().ListTools()
	original := map[string][]byte{}
	for n, v := range before {
		b, e := json.Marshal(v.Tool)
		if e != nil {
			t.Fatal(e)
		}
		original[n] = b
	}
	s.addGraphTools()
	after := s.MCP().ListTools()
	for n, b := range original {
		a, e := json.Marshal(after[n].Tool)
		if e != nil || !reflect.DeepEqual(a, b) {
			t.Fatal("changed original descriptor", n)
		}
	}
	for _, n := range []string{"graph_source", "dependency_graph", "graph_exports", "graph_ast", "graph_stats"} {
		if after[n] == nil {
			t.Fatal("missing tool", n)
		}
	}
	a := graphArgs{Dir: "/project", SourceInput: "/public/source.json", Selectors: []string{"base.skill.review"}, MaxBytes: 32768}
	args := graphArgv("exports", a)
	if len(args) < 8 || args[0] != "graph" || args[1] != "exports" {
		t.Fatal("not shared CLI route")
	}
}

var graphExport = flag.String("graph-domain-export", "", "Existing external directory for reviewable registry/schema union proposals")

func TestGraphDomainReviewableUnion(t *testing.T) {
	if *graphExport == "" {
		t.Skip("explicit external proposal export")
	}
	s := New("/nonexistent", "test", nil)
	defer s.Close()
	s.addGraphTools()
	tools := s.MCP().ListTools()
	names := []string{}
	entries := []json.RawMessage{}
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, e := json.Marshal(tools[name].Tool)
		if e != nil {
			t.Fatal(e)
		}
		entries = append(entries, b)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if e := enc.Encode(entries); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(*graphExport, "tools.schema.golden.json"), buf.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	nameBytes := []byte{}
	for _, name := range names {
		nameBytes = append(nameBytes, []byte(name+"\n")...)
	}
	if e := os.WriteFile(filepath.Join(*graphExport, "tools.golden.txt"), nameBytes, 0600); e != nil {
		t.Fatal(e)
	}
	schema, e := resultdto.GenerateSchema()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(*graphExport, "result.v1.schema.json"), schema, 0600); e != nil {
		t.Fatal(e)
	}
}

var graphEncoderBaseline = flag.String("graph-encoder-baseline", "", "External original-encoder receipt directory")
var graphWriteBaseline = flag.Bool("graph-write-baseline", false, "Emit baseline only with the pinned original result.go Go overlay")

func TestGraphOriginal30SerializerParity(t *testing.T) {
	if *graphEncoderBaseline == "" {
		t.Skip("explicit baseline receipt directory required")
	}
	s := New("/not-executable", "test", nil)
	defer s.Close()
	names := []string{}
	for name := range s.MCP().ListTools() {
		if !graphTool(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) != 30 {
		t.Fatal("original inventory changed", len(names))
	}
	for _, name := range names {
		ops := toolOperations[name]
		if len(ops) == 0 {
			t.Fatal(name, "missing operation")
		}
		for _, failure := range []bool{false, true} {
			env := resultdto.New(ops[0], "original<\\\"&é")
			if scope, _ := resultdto.ScopeForOperation(ops[0]); scope == resultdto.ScopeProject {
				env.Project = &resultdto.Project{ID: "p", Root: "/public/<root>\\\"&é"}
			}
			env.Summary.FilesChanged = 3
			env.Diagnostics = []resultdto.Diagnostic{{Code: "PUBLIC", Severity: "warning", Message: "<\\\"&é\n"}}
			// Detached data exercises escaping, not a source admission fixture.
			_ = env.SetData(map[string]any{"observed": "<\\\"&é\n"})
			encoded, err := json.Marshal(structuredResult(env, failure))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(*graphEncoderBaseline, fmt.Sprintf("%s-%t.json", name, failure))
			if *graphWriteBaseline {
				if err = os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				before, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, encoded) {
					t.Fatal("original wire changed", name, failure, err)
				}
			}
		}
	}
	t.Log("30 original tool encoder cases, success/error, byte-identical; no tool execution")
}

type graphHarness struct {
	input  *io.PipeWriter
	output *bufio.Reader
	read   *io.PipeReader
	g      *graphTransport
	done   chan error
	cancel context.CancelFunc
}

func graphSDKHarness(t *testing.T, s *Server) *graphHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	in, iw := io.Pipe()
	or, ow := io.Pipe()
	g := newGraphTransport(ctx, s, &rootCancellationReader{in: in, frames: s.rootFrames}, &rootResponseWriter{frames: s.rootFrames, server: s, out: ow}, nil)
	stdio := server.NewStdioServer(s.mcp)
	stdio.SetContextFunc(g.bindSession)
	h := &graphHarness{iw, bufio.NewReader(or), or, g, make(chan error, 1), cancel}
	go func() { h.done <- stdio.Listen(ctx, g, g) }()
	t.Cleanup(func() {
		cancel()
		iw.Close()
		or.Close()
		ow.Close()
		in.Close()
		g.close()
		<-h.done
		s.Close()
	})
	h.send(t, `{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"public-test","version":"1"}}}`)
	h.recv(t)
	h.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return h
}
func (h *graphHarness) send(t *testing.T, raw string) {
	t.Helper()
	if _, err := io.WriteString(h.input, raw+"\n"); err != nil {
		t.Fatal(err)
	}
}
func (h *graphHarness) recv(t *testing.T) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() { raw, _ := h.output.ReadBytes('\n'); ch <- raw }()
	select {
	case raw := <-ch:
		if len(raw) == 0 {
			t.Fatal("missing frame")
		}
		return raw
	case <-time.After(4 * time.Second):
		t.Fatal("SDK frame timeout")
		return nil
	}
}
func graphProtocolEnvelope(t *testing.T) []byte {
	t.Helper()
	env := resultdto.New(resultdto.OperationGraphStats, "test")
	env.Project = &resultdto.Project{ID: "p", Root: "/public/project"}
	_ = env.SetData(resultdto.GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: "stats", QueryDigest: "sha256:" + strings.Repeat("1", 64), InputDigests: []string{}, FullGraphDigest: "sha256:" + strings.Repeat("2", 64), ObservationBasis: "installed-project-syntax", VerificationLevel: "syntax", CacheState: "missing", GraphStatus: "ok", Records: []resultdto.GraphRecord{}, Page: resultdto.GraphPage{Representation: "whole", Digest: "sha256:" + strings.Repeat("3", 64)}, Stats: map[string]resultdto.GraphLayerStats{}})
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestGraphSDKSessionRefusalsAndCleanup(t *testing.T) {
	runner := execx.NewRecordingRunner().SetDefault(execx.Response{Result: execx.Result{Stdout: string(graphProtocolEnvelope(t))}})
	s := New("/not-executable", "test", runner)
	s.SetLimits(Limits{DefaultTimeout: time.Second})
	h := graphSDKHarness(t, s)
	// Oversized escaped ID is refused before ANY child work.
	id, _ := json.Marshal(strings.Repeat("<\\\"&", 4000))
	h.send(t, `{"jsonrpc":"2.0","id":`+string(id)+`,"method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":"/public/project","maxBytes":32768}}}`)
	raw := h.recv(t)
	if len(raw) > 32768 || !bytes.Contains(raw, []byte(`"id":null`)) {
		t.Fatal("unbounded metadata refusal")
	}
	if len(runner.Calls) != 0 {
		t.Fatal("metadata refusal invoked child")
	}
	for i := 0; i < 64; i++ {
		h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"graph_stats","_meta":1,"arguments":{"dir":"/public/project"}}}`, i))
		raw = h.recv(t)
		if !bytes.Contains(raw, []byte(`"error"`)) {
			t.Fatal("SDK decode error missing")
		}
	}
	h.send(t, strings.ReplaceAll(`{"jsonrpc":"2.0","id":"valid<\\\"&","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":"/public/project","maxBytes":32768}}}`, "/public/project", t.TempDir()))
	raw = h.recv(t)
	if !bytes.Contains(raw, []byte(`"graph.stats"`)) || len(raw) > 32768 {
		t.Fatal("valid call after decode failures", string(raw))
	}
	if len(runner.Calls) != 1 {
		t.Fatal("slot leak or extra child")
	}
	deadline := time.Now().Add(time.Second)
	for {
		h.g.mu.Lock()
		n := len(h.g.active)
		h.g.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("records leaked")
		}
		time.Sleep(time.Millisecond)
	}
	// Unrelated SDK route traverses the exact original input/output path.
	line := ` {"jsonrpc":"2.0","id":"ping","method":"ping"} `
	h.send(t, line)
	raw = h.recv(t)
	if string(raw) != "{\"jsonrpc\":\"2.0\",\"id\":\"ping\",\"result\":{}}\n" {
		t.Fatal("unrelated SDK frame changed", string(raw))
	}
}

// Protocol-only runner records actual SDK handler entry; it supplies no source
// authority and never substitutes for the separately installed consumer proof.
type graphBlockingRunner struct {
	entered chan struct{}
	once    sync.Once
}

func (r *graphBlockingRunner) Run(ctx context.Context, _ string, _ []string, _ execx.Options) (execx.Result, error) {
	r.once.Do(func() { close(r.entered) })
	<-ctx.Done()
	return execx.Result{}, ctx.Err()
}
func (*graphBlockingRunner) LookPath(string) (string, error) { return "", errors.New("not used") }
func TestGraphSDKDuplicateCancellationAndDeadline(t *testing.T) {
	runner := &graphBlockingRunner{entered: make(chan struct{})}
	s := New("/not-executable", "test", runner)
	s.SetLimits(Limits{DefaultTimeout: 500 * time.Millisecond})
	h := graphSDKHarness(t, s)
	dir, _ := json.Marshal(t.TempDir())
	h.send(t, `{"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	select {
	case <-runner.entered:
	case <-time.After(time.Second):
		t.Fatal("registered handler never called")
	}
	h.g.mu.Lock()
	original := h.g.active[`"active"`]
	h.g.mu.Unlock()
	if original == nil {
		t.Fatal("no owned call")
	}
	// Unrelated same-ID SDK response must preserve the original owned request.
	h.send(t, `{"jsonrpc":"2.0","id":"active","method":"ping"}`)
	raw := h.recv(t)
	if !bytes.Contains(raw, []byte(`"result":{}`)) {
		t.Fatal("unrelated ping changed")
	}
	h.g.mu.Lock()
	same := h.g.active[`"active"`] == original
	h.g.mu.Unlock()
	if !same {
		t.Fatal("unrelated response released graph owner")
	}
	h.send(t, `{"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	raw = h.recv(t)
	if !bytes.Contains(raw, []byte(`"id":null`)) {
		t.Fatal("duplicate did not bounded-refuse")
	}
	h.g.mu.Lock()
	same = h.g.active[`"active"`] == original
	h.g.mu.Unlock()
	if !same {
		t.Fatal("duplicate released original")
	}
	h.send(t, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"active","reason":"public counter"}}`)
	deadline := time.Now().Add(time.Second)
	for {
		h.g.mu.Lock()
		n := len(h.g.active)
		h.g.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled owner leaked")
		}
		time.Sleep(time.Millisecond)
	}
	// The transport remains usable; cancellation is scoped to that graph call.
	h.send(t, `{"jsonrpc":"2.0","id":"alive","method":"ping"}`)
	if !bytes.Contains(h.recv(t), []byte(`"id":"alive"`)) {
		t.Fatal("cancel killed unrelated transport")
	}
	h.send(t, `{"jsonrpc":"2.0","id":"deadline","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	deadline = time.Now().Add(time.Second)
	for {
		h.g.mu.Lock()
		started := h.g.active[`"deadline"`] != nil
		h.g.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deadline call never admitted")
		}
		time.Sleep(time.Millisecond)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		h.g.mu.Lock()
		n := len(h.g.active)
		h.g.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deadline leaked")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestGraphSDKOutputSchemaAndBrokenWrite(t *testing.T) {
	s := New("/not-executable", "test", nil)
	// Same SDK registry/validation, intentionally malformed handler RESULT only.
	tool := s.MCP().ListTools()["graph_stats"].Tool
	s.MCP().AddTool(tool, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultStructured(map[string]any{"invalid": "public counter"}, "invalid"), nil
	})
	h := graphSDKHarness(t, s)
	dir, _ := json.Marshal(t.TempDir())
	h.send(t, `{"jsonrpc":"2.0","id":"schema","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	raw := h.recv(t)
	var response struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Error) == 0 && !response.Result.IsError || len(raw) > 32768 {
		t.Fatal("SDK output schema did not refuse", string(raw))
	}
	deadline := time.Now().Add(time.Second)
	for {
		h.g.mu.Lock()
		n := len(h.g.active)
		h.g.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("schema owner leaked")
		}
		time.Sleep(time.Millisecond)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read.Close()
	defer write.Close()
	g := newGraphTransport(context.Background(), s, strings.NewReader(""), write, write)
	defer g.close()
	if err = g.writeGraph(context.Background(), []byte("one complete frame\n")); err == nil {
		t.Fatal("broken pipe accepted")
	}
}

func TestGraphSDKCapacityAndBlockedOutput(t *testing.T) {
	runner := &graphBlockingRunner{entered: make(chan struct{})}
	s := New("/not-executable", "test", runner)
	s.SetLimits(Limits{DefaultTimeout: 10 * time.Second})
	h := graphSDKHarness(t, s)
	dir, _ := json.Marshal(t.TempDir())
	for i := 0; i < 64; i++ {
		h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":"call-%d","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":%s}}}`, i, dir))
	}
	h.send(t, `{"jsonrpc":"2.0","id":"overflow","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	raw := h.recv(t)
	if !bytes.Contains(raw, []byte(`"id":null`)) {
		t.Fatal("65th graph call not bounded-refused")
	}
	h.g.mu.Lock()
	count := len(h.g.active)
	h.g.mu.Unlock()
	if count != 64 {
		t.Fatal("concurrent64 limit", count)
	}
	h.g.cancel()
	h.g.close()
	h.g.mu.Lock()
	count = len(h.g.active)
	h.g.mu.Unlock()
	if count != 0 {
		t.Fatal("concurrent canceled calls leaked")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	fd := int(write.Fd())
	if err = unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	fill := 0
	for {
		n, e := unix.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if n > 0 {
			fill += n
		}
		if e == unix.EAGAIN {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	// Go's pipe is pollable. Keep its nonblocking descriptor for deadline support.
	g := newGraphTransport(context.Background(), s, strings.NewReader(""), write, write)
	defer g.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = g.writeGraph(ctx, []byte("complete graph frame\n"))
	if err == nil || time.Since(start) > time.Second || time.Since(start) < 15*time.Millisecond {
		t.Fatal("blocked output deadline unbounded", err)
	}
	drained := make([]byte, fill)
	if _, err = io.ReadFull(read, drained); err != nil {
		t.Fatal(err)
	}
	// The graph deadline must not leak into the next unrelated SDK frame.
	if _, err = g.Write([]byte("other frame\n")); err != nil {
		t.Fatal("graph deadline changed unrelated output", err)
	}
	exact := make([]byte, len("other frame\n"))
	if _, err = io.ReadFull(read, exact); err != nil || string(exact) != "other frame\n" {
		t.Fatal("unrelated bytes changed", err)
	}
	t.Log("64 concurrent SDK graph calls capped and canceled cleanly; actual full pipe deadline bounded, unrelated frame unchanged")
}

func TestGraphSDKFinalByteMismatch(t *testing.T) {
	runner := execx.NewRecordingRunner().SetDefault(execx.Response{Result: execx.Result{Stdout: string(graphProtocolEnvelope(t))}})
	s := New("/not-executable", "test", runner)
	s.MCP().GetHooks().AddAfterCallTool(func(_ context.Context, _ any, _ *mcp.CallToolRequest, result any) {
		if out, ok := result.(*mcp.CallToolResult); ok {
			out.Content = append(out.Content, mcp.TextContent{Type: "text", Text: "after-handler public mutation"})
		}
	})
	h := graphSDKHarness(t, s)
	dir, _ := json.Marshal(t.TempDir())
	h.send(t, `{"jsonrpc":"2.0","id":"mismatch","method":"tools/call","params":{"name":"graph_stats","arguments":{"dir":`+string(dir)+`}}}`)
	raw := h.recv(t)
	if !bytes.Equal(raw, graphNullRefusal()) {
		t.Fatal("SDK after-handler mutation escaped exact-frame guard", string(raw))
	}
	if len(runner.Calls) != 1 {
		t.Fatal("real registered handler not called")
	}
}

func TestGraphOriginal30InputForwarding(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	count := 0
	for name := range s.MCP().ListTools() {
		if graphTool(name) {
			continue
		}
		// Even invalid arguments on unrelated tools must retain original SDK handling.
		raw := fmt.Sprintf(" {\"jsonrpc\":\"2.0\",\"id\":\"<\\\\&\",\"method\":\"tools/call\",\"params\":{\"name\":%q,\"arguments\":{\"opaque\":[1,2]},\"_meta\":1}} \n", name)
		g := newGraphTransport(context.Background(), s, &rootCancellationReader{in: strings.NewReader(raw), frames: s.rootFrames}, io.Discard, nil)
		received, err := io.ReadAll(g)
		g.close()
		if err != nil || string(received) != raw {
			t.Fatal("unrelated input bytes changed", name, err)
		}
		count++
	}
	if count != 30 {
		t.Fatal("original route inventory changed", count)
	}
	t.Log("all original30 raw request lines forwarded byte-for-byte; no tool executed")
}

// A preceding ordinary frame owns the descriptor and must remain blocked while
// graph workers abandon acquisition. No graph deadline may touch its write.
func TestGraphOrdinaryHolderCleanup(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			s := New("/not-executable", "test", nil)
			defer s.Close()
			timeout := 10 * time.Second
			if mode == "deadline" {
				timeout = 150 * time.Millisecond
			}
			s.SetLimits(Limits{DefaultTimeout: timeout})
			tool := s.MCP().ListTools()["graph_stats"].Tool
			s.MCP().AddTool(tool, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultError("public transport counter"), nil
			})
			read, write, fill := graphFullPipe(t)
			defer read.Close()
			defer write.Close()
			dir, _ := json.Marshal(t.TempDir())
			var input strings.Builder
			for i := 0; i < 64; i++ {
				fmt.Fprintf(&input, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"graph_stats\",\"arguments\":{\"dir\":%s}}}\n", i, dir)
			}
			input.WriteString("{\"jsonrpc\":\"2.0\",\"id\":\"ordinary\",\"method\":\"ping\"}\n")
			g := newGraphTransport(context.Background(), s, strings.NewReader(input.String()), write, write)
			g.bindSession(context.Background())
			holder := make(chan error, 1)
			go func() { _, e := g.Write([]byte("ordinary frame\n")); holder <- e }()
			graphWait(t, func() bool { return len(g.writeGate) == 1 })
			// Read consumes all graph calls and returns only the unchanged ordinary line.
			b := make([]byte, 256)
			n, e := g.Read(b)
			if e != nil || !bytes.Contains(b[:n], []byte(`"method":"ping"`)) {
				t.Fatal("input", e)
			}
			g.mu.Lock()
			count := len(g.active)
			g.mu.Unlock()
			if count != 64 {
				t.Fatal("64 workers not admitted", count)
			}
			if mode == "cancel" {
				g.mu.Lock()
				for _, c := range g.active {
					c.cancel()
				}
				g.mu.Unlock()
			}
			done := make(chan struct{})
			if mode == "close" {
				go func() { g.close(); close(done) }()
			} else {
				go func() { g.workers.Wait(); close(done) }()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("workers retained behind ordinary write")
			}
			g.mu.Lock()
			count = len(g.active)
			g.mu.Unlock()
			if count != 0 {
				t.Fatal("records leaked", count)
			}
			select {
			case e := <-holder:
				t.Fatal("graph changed ordinary deadline", e)
			default:
			}
			// Drain only AFTER graph cleanup has completed; verify exact ordinary bytes.
			if _, e = io.ReadFull(read, make([]byte, fill)); e != nil {
				t.Fatal(e)
			}
			raw := make([]byte, len("ordinary frame\n"))
			if _, e = io.ReadFull(read, raw); e != nil || string(raw) != "ordinary frame\n" {
				t.Fatal("ordinary bytes", e)
			}
			if e = <-holder; e != nil {
				t.Fatal("ordinary write", e)
			}
			g.close()
		})
	}
}

func graphWait(t *testing.T, ready func() bool) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for !ready() {
		if time.Now().After(until) {
			t.Fatal("transport state wait expired")
		}
		time.Sleep(time.Millisecond)
	}
}
func graphFullPipe(t *testing.T) (*os.File, *os.File, int) {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	fd := int(w.Fd())
	if e = unix.SetNonblock(fd, true); e != nil {
		t.Fatal(e)
	}
	fill := 0
	for {
		n, e := unix.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if n > 0 {
			fill += n
		}
		if e == unix.EAGAIN {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	return r, w, fill
}

func TestGraphPrehandlerRefusalFullPipe(t *testing.T) {
	for _, preceding := range []bool{false, true} {
		t.Run(strconv.FormatBool(preceding), func(t *testing.T) {
			s := New("/not-executable", "test", nil)
			defer s.Close()
			r, w, fill := graphFullPipe(t)
			defer r.Close()
			defer w.Close()
			// Invalid null ID is a pre-handler refusal with no caller deadline.
			g := newGraphTransport(context.Background(), s, strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"tools/call\",\"params\":{\"name\":\"graph_stats\",\"arguments\":{}}}\n"), w, w)
			g.bindSession(context.Background())
			stopped := make(chan struct{})
			g.stopStdio = func() { close(stopped) }
			var holder chan error
			if preceding {
				holder = make(chan error, 1)
				go func() { _, e := g.Write([]byte("ordinary frame\n")); holder <- e }()
				graphWait(t, func() bool { return len(g.writeGate) == 1 })
			}
			result := make(chan error, 1)
			start := time.Now()
			go func() { _, e := g.Read(make([]byte, 256)); result <- e }()
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("full output accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("refusal blocked input indefinitely")
			}
			if time.Since(start) < graphRefusalWriteBudget/2 {
				t.Fatal("did not exercise blocked refusal")
			}
			select {
			case <-stopped:
			default:
				t.Fatal("failed refusal not terminal")
			}
			g.close()
			if preceding {
				select {
				case e := <-holder:
					t.Fatal("refusal changed ordinary deadline", e)
				default:
				}
			}
			if _, e := io.ReadFull(r, make([]byte, fill)); e != nil {
				t.Fatal(e)
			}
			if preceding {
				b := make([]byte, len("ordinary frame\n"))
				if _, e := io.ReadFull(r, b); e != nil || string(b) != "ordinary frame\n" {
					t.Fatal("ordinary frame", e)
				}
				if e := <-holder; e != nil {
					t.Fatal(e)
				}
			}
			// No extra refusal is appended after terminal failure.
			if e := r.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			if n, e := r.Read(make([]byte, 256)); n != 0 || e == nil {
				t.Fatal("unexpected extra response", n, e)
			}
		})
	}
}

var graphScalarReceipts = flag.String("graph-scalar-receipts", "", "Existing external directory for exact scalar SDK frames")

func graphScalarReceipt(t *testing.T, name string, raw []byte) {
	t.Helper()
	if *graphScalarReceipts != "" {
		if err := os.WriteFile(filepath.Join(*graphScalarReceipts, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// These are real native graph/selector values through the SDK validator, not
// source-admission or installed-project claims. Both RawMessage positions carry
// nonempty scalar parameters and preserve native graph/export identity.
func TestGraphNativeScalarSDKValidation(t *testing.T) {
	params := []deps.Parameter{{Name: "label", Value: json.RawMessage(`"neutral guide"`)}, {Name: "enabled", Value: json.RawMessage(`true`)}, {Name: "count", Value: json.RawMessage(`9007199254740991`)}}
	pin := deps.PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "base", ProviderID: "provider.base", Origin: "https://example.test/base", TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat("1", 40), TreeDigest: "sha256:" + strings.Repeat("2", 64), ContentDigest: "sha256:" + strings.Repeat("3", 64), ContractDigest: "sha256:" + strings.Repeat("4", 64), EvidenceDigest: "sha256:" + strings.Repeat("5", 64), Parameters: params, Dependencies: []string{}}
	sort.Slice(pin.Parameters, func(i, j int) bool { return pin.Parameters[i].Name < pin.Parameters[j].Name })
	params = pin.Parameters
	g, e := deps.BuildSourceGraph([]deps.PinnedSource{pin})
	if e != nil {
		t.Fatal(e)
	}
	ep := []exports.ScalarParameter{}
	for _, p := range params {
		ep = append(ep, exports.ScalarParameter{Name: p.Name, Value: append(json.RawMessage{}, p.Value...)})
	}
	cat := exports.Catalog{APIVersion: exports.CatalogAPIVersion, Source: g.Nodes[0].Key, Provider: pin.ProviderID, ContractDigest: pin.ContractDigest, Exports: []exports.ExportEntry{{ID: "notes", Domain: "block", Name: "notes", Version: "0.1.0", ContentDigest: pin.ContentDigest, ToolDigest: pin.TreeDigest, Parameters: ep, Requires: []exports.ExportRequirement{}}}}
	eg, e := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: "base.block.notes", Bindings: ep}}, g, []exports.Catalog{cat})
	if e != nil {
		t.Fatal(e)
	}
	identity, e := exports.SelectedExportIdentity(eg.Selected[0])
	if e != nil {
		t.Fatal(e)
	}
	records := []resultdto.GraphRecord{{Kind: "source", Identity: g.Nodes[0].Key, Source: &g.Nodes[0], Pins: []deps.PinnedSource{pin}}, {Kind: "export", Identity: identity, Export: &eg.Selected[0]}}
	rb, e := canonicaljson.Canonical(records)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(rb)
	data := resultdto.GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: "source", QueryDigest: g.Digest, ObservationBasis: "enrolled-source-selection", InputDigests: []string{g.Digest, eg.Digest}, FullGraphDigest: g.Digest, VerificationLevel: "authenticated-source-pins", CacheState: "disabled", GraphStatus: "ok", Records: records, Page: resultdto.GraphPage{Representation: "whole", Digest: fmt.Sprintf("sha256:%x", sum), Returned: 2, Total: 2}}
	raw, e := json.Marshal(data)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = resultdto.DecodeGraphData(raw); e != nil {
		t.Fatal(e)
	}
	for _, spec := range []struct {
		name string
		op   resultdto.Operation
	}{{"graph_source", resultdto.OperationGraphSource}, {"dependency_graph", resultdto.OperationGraphSource}, {"graph_exports", resultdto.OperationGraphExports}, {"graph_ast", resultdto.OperationGraphAST}, {"graph_stats", resultdto.OperationGraphStats}} {
		t.Run(spec.name, func(t *testing.T) {
			s := New("/not-executable", "test", nil)
			defer s.Close()
			env := resultdto.New(spec.op, "test")
			if e := env.SetData(data); e != nil {
				t.Fatal(e)
			}
			tool := s.MCP().ListTools()[spec.name].Tool
			s.MCP().AddTool(tool, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return structuredResult(env, false), nil
			})
			h := graphSDKHarness(t, s)
			request := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":\"scalar\",\"method\":\"tools/call\",\"params\":{\"name\":%q,\"arguments\":{}}}", spec.name)
			h.send(t, request)
			got := h.recv(t)
			var response struct {
				Result struct {
					IsError    bool `json:"isError"`
					Structured struct {
						Data resultdto.GraphData `json:"data"`
					} `json:"structuredContent"`
				} `json:"result"`
				Error json.RawMessage `json:"error"`
			}
			if e := json.Unmarshal(got, &response); e != nil || len(response.Error) > 0 || response.Result.IsError {
				t.Fatal("valid native scalars refused", string(got), e)
			}
			graphScalarReceipt(t, spec.name+"-success.json", got)
			after := response.Result.Structured.Data
			if !reflect.DeepEqual(after.Records, records) {
				t.Fatal("scalar bytes/native identity changed")
			}
			for _, position := range []string{"export", "pins"} {
				for badIndex, bad := range []string{`null`, `[1]`, `{"k":1}`, `1.5`, `9007199254740992`} {
					if deps.ValidateScalarParameter([]byte(bad)) == nil {
						t.Fatal("native facet widened", bad)
					}
					var value map[string]any
					_ = json.Unmarshal(raw, &value)
					rs := value["records"].([]any)
					var parameter map[string]any
					if position == "export" {
						parameter = rs[1].(map[string]any)["export"].(map[string]any)["parameters"].([]any)[0].(map[string]any)
					} else {
						parameter = rs[0].(map[string]any)["pins"].([]any)[0].(map[string]any)["parameters"].([]any)[0].(map[string]any)
					}
					var invalid any
					_ = json.Unmarshal([]byte(bad), &invalid)
					parameter["value"] = invalid
					invalidEnv := resultdto.New(spec.op, "test")
					if e := invalidEnv.SetData(value); e != nil {
						t.Fatal(e)
					}
					graphWait(t, func() bool { h.g.mu.Lock(); defer h.g.mu.Unlock(); return len(h.g.active) == 0 })
					env = invalidEnv
					h.send(t, request)
					b := h.recv(t)
					graphScalarReceipt(t, fmt.Sprintf("%s-%s-refusal-%d.json", spec.name, position, badIndex), b)
					var refusal struct {
						Result struct {
							IsError bool `json:"isError"`
						} `json:"result"`
					}
					if json.Unmarshal(b, &refusal) != nil || !refusal.Result.IsError {
						t.Fatal("SDK accepted invalid scalar", position, bad, string(b))
					}
				}
			}
			t.Log("actual SDK accepted nonempty string/bool/safe integer at both native positions; bytes/IDs preserved; null/array/object/fraction/unsafe integer refused")
		})
	}
	for _, bad := range []string{`1.0`, `1e0`, `-0`} {
		if deps.ValidateScalarParameter([]byte(bad)) == nil {
			t.Fatal("native lexical gate widened", bad)
		}
	}
}
