package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
)

var batchReceiptSequence atomic.Int32
var batchArtifactDir = flag.String("batch-artifacts", "", "external batch schema/receipt evidence directory")

func batchWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("batch cleanup did not complete")
		}
		time.Sleep(time.Millisecond)
	}
}

type batchSDKHarness struct {
	input  *io.PipeWriter
	output *bufio.Reader
	read   *io.PipeReader
	batch  *batchTransport
}

func batchHarness(t *testing.T, s *Server) *batchSDKHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	in, iw := io.Pipe()
	or, ow := io.Pipe()
	g := newGraphTransport(ctx, s, &rootCancellationReader{in: in, frames: s.rootFrames}, &rootResponseWriter{frames: s.rootFrames, server: s, out: ow}, nil)
	b := newBatchTransport(ctx, s, g)
	h := &batchSDKHarness{iw, bufio.NewReader(or), or, b}
	stdio := server.NewStdioServer(s.mcp)
	stdio.SetContextFunc(b.bindSession)
	done := make(chan error, 1)
	go func() { done <- stdio.Listen(ctx, b, b) }()
	t.Cleanup(func() {
		cancel()
		iw.Close()
		or.Close()
		ow.Close()
		in.Close()
		b.close()
		g.close()
		<-done
		s.Close()
	})
	h.send(t, `{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"public-test","version":"1"}}}`)
	h.recv(t)
	h.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return h
}
func (h *batchSDKHarness) send(t *testing.T, line string) {
	t.Helper()
	if _, e := io.WriteString(h.input, line+"\n"); e != nil {
		t.Fatal(e)
	}
}
func (h *batchSDKHarness) recv(t *testing.T) []byte {
	t.Helper()
	done := make(chan []byte, 1)
	go func() { line, _ := h.output.ReadBytes('\n'); done <- line }()
	select {
	case line := <-done:
		if len(line) == 0 {
			t.Fatal("empty SDK frame")
		}
		if *batchArtifactDir != "" {
			if e := os.MkdirAll(*batchArtifactDir, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(*batchArtifactDir, fmt.Sprintf("actual-sdk-frame-%03d.json", batchReceiptSequence.Add(1))), line, 0600); e != nil {
				t.Fatal(e)
			}
		}
		return line
	case <-time.After(time.Second):
		t.Fatal("SDK frame timeout")
		return nil
	}
}
func TestBatchSDKDecodeCleanupAndOwnedDuplicate(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	var called atomic.Int32
	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	s.MCP().AddTool(mcp.NewTool("run_batch"), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		call, ok := ctx.Value(batchCallKey{}).(*batchCall)
		if !ok || !call.sdkBound {
			return nil, resultwire.ErrBatchBinding
		}
		called.Add(1)
		if req.GetBool("hold", false) {
			entered <- struct{}{}
			select {
			case <-hold:
			case <-call.ctx.Done():
			}
		}
		return mcp.NewToolResultError("public codec counter"), nil
	})
	h := batchHarness(t, s)
	for i := 0; i < 64; i++ {
		h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"run_batch","_meta":1,"arguments":{}}}`, i))
		h.recv(t)
	}
	batchWait(t, func() bool { h.batch.mu.Lock(); defer h.batch.mu.Unlock(); return len(h.batch.active) == 0 })
	if called.Load() != 0 {
		t.Fatal("malformed metadata reached handler")
	}
	h.send(t, `{"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"run_batch","arguments":{"hold":true}}}`)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("owned handler not entered")
	}
	h.batch.mu.Lock()
	original := h.batch.active[`"active"`]
	h.batch.mu.Unlock()
	h.send(t, `{"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"run_batch","_meta":1,"arguments":{}}}`)
	refused := h.recv(t)
	if !bytes.Contains(refused, []byte(`"id":null`)) {
		t.Fatal("duplicate owned allocation not refused")
	}
	h.batch.mu.Lock()
	same := h.batch.active[`"active"`] == original
	h.batch.mu.Unlock()
	if !same || original.ctx.Err() != nil {
		t.Fatal("duplicate displaced active lease")
	}
	close(hold)
	h.recv(t)
	batchWait(t, func() bool { h.batch.mu.Lock(); defer h.batch.mu.Unlock(); return len(h.batch.active) == 0 })
}
func TestBatchWorkersCancelBehindOrdinaryWriter(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			s := New("/nonexistent", "test", nil)
			s.limits.LongTimeout = 150 * time.Millisecond
			var handled atomic.Int32
			s.MCP().AddTool(mcp.NewTool("run_batch"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				handled.Add(1)
				return mcp.NewToolResultError("bounded batch counter"), nil
			})
			read, write, fill := graphFullPipe(t)
			defer read.Close()
			defer write.Close()
			var input strings.Builder
			for i := 0; i < 64; i++ {
				fmt.Fprintf(&input, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"tools/call\",\"params\":{\"name\":\"run_batch\",\"arguments\":{}}}\n", i)
			}
			input.WriteString("{\"jsonrpc\":\"2.0\",\"id\":\"ordinary\",\"method\":\"ping\"}\n")
			g := newGraphTransport(context.Background(), s, strings.NewReader(input.String()), write, write)
			b := newBatchTransport(context.Background(), s, g)
			b.bindSession(context.Background())
			holder := make(chan error, 1)
			go func() { _, e := g.Write([]byte("ordinary frame\n")); holder <- e }()
			batchWait(t, func() bool { return len(g.writeGate) == 1 })
			buf := make([]byte, 256)
			n, e := b.Read(buf)
			if e != nil || !bytes.Contains(buf[:n], []byte(`"method":"ping"`)) {
				t.Fatal("ordinary input bytes changed", e)
			}
			if mode == "cancel" {
				b.mu.Lock()
				for _, c := range b.active {
					c.cancel()
				}
				b.mu.Unlock()
			}
			done := make(chan struct{})
			go func() {
				if mode == "close" {
					b.close()
				} else {
					b.workers.Wait()
				}
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("batch workers retained behind ordinary frame")
			}
			b.mu.Lock()
			left := len(b.active)
			b.mu.Unlock()
			if left != 0 {
				t.Fatal("owned records retained", left)
			}
			if handled.Load() != 64 {
				t.Fatal("actual SDK handler count", handled.Load())
			}
			select {
			case e := <-holder:
				t.Fatal("ordinary deadline changed", e)
			default:
			}
			if _, e = io.ReadFull(read, make([]byte, fill)); e != nil {
				t.Fatal(e)
			}
			raw := make([]byte, len("ordinary frame\n"))
			if _, e = io.ReadFull(read, raw); e != nil || string(raw) != "ordinary frame\n" {
				t.Fatal("ordinary frame changed", e)
			}
			if e = <-holder; e != nil {
				t.Fatal(e)
			}
			b.close()
			g.close()
		})
	}
}
func TestBatchPrehandlerRefusalHasFiniteWriteBudget(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	var calls atomic.Int32
	s.MCP().AddTool(mcp.NewTool("run_batch"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return mcp.NewToolResultError("unexpected"), nil
	})
	read, write, fill := graphFullPipe(t)
	defer read.Close()
	defer write.Close()
	input := `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"run_batch","arguments":{}}}` + "\n"
	g := newGraphTransport(context.Background(), s, strings.NewReader(input), write, write)
	b := newBatchTransport(context.Background(), s, g)
	b.bindSession(context.Background())
	holder := make(chan error, 1)
	go func() { _, e := g.Write([]byte("ordinary frame\n")); holder <- e }()
	batchWait(t, func() bool { return len(g.writeGate) == 1 })
	done := make(chan error, 1)
	go func() { _, e := b.Read(make([]byte, 256)); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("blocked refusal accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("prehandler reader blocked indefinitely")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached work")
	}
	select {
	case e := <-holder:
		t.Fatal("ordinary writer deadline changed", e)
	default:
	}
	if _, e := io.ReadFull(read, make([]byte, fill)); e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, len("ordinary frame\n"))
	io.ReadFull(read, raw)
	if string(raw) != "ordinary frame\n" {
		t.Fatal("ordinary bytes changed")
	}
	if e := <-holder; e != nil {
		t.Fatal(e)
	}
	b.close()
	g.close()
}
func TestBatchSchemaAndArtifactExport(t *testing.T) {
	data, e := batchDataSchema()
	if e != nil {
		t.Fatal(e)
	}
	output, e := toolOutputSchema(resultdto.OperationProjectRunBatch)
	if e != nil {
		t.Fatal(e)
	}
	// The exact descriptor is the producer-owned public B1 declaration. This
	// export is presentation data only, not a registered execution alternative.
	tool := mcp.NewTool("run_batch", mcp.WithDescription("Prepare or execute a finite ordered authenticated readonly native command batch; ONE operation, complete signed approval vector, no shell or child-process widening."), mcp.WithString("dir", mcp.Required(), mcp.Description("Authenticated installed project root")), mcp.WithString("projectContext", mcp.Description("Exact authenticated installed context key")), mcp.WithString("input", mcp.Required(), mcp.Description("Closed run-batch-input/v1 JSON, 1..16 ordered typed steps")), mcp.WithBoolean("prepare", mcp.Description("Report finalized requests without import or execution")), mcp.WithArray("approvals", mcp.Description("Complete ordered persistent signed approval digest vector"), mcp.Items(map[string]any{"type": "string"})), mcp.WithString("approvalInput", mcp.Description("Public signed approval document array path")), outputSchema(resultdto.OperationProjectRunBatch))
	descriptor, e := json.Marshal(tool)
	if e != nil {
		t.Fatal(e)
	}
	if *batchArtifactDir != "" {
		if !filepath.IsAbs(*batchArtifactDir) {
			t.Fatal("external artifact path required")
		}
		if e = os.MkdirAll(*batchArtifactDir, 0700); e != nil {
			t.Fatal(e)
		}
		generic, e := resultdto.GenerateSchema()
		if e != nil {
			t.Fatal(e)
		}
		for name, raw := range map[string][]byte{"batch-data.schema.json": data, "batch-output.schema.json": output, "batch-tool.json": descriptor, "result.v1.schema.json": generic} {
			if e = os.WriteFile(filepath.Join(*batchArtifactDir, name), raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func batchSDKFactualEnvelope(t *testing.T) resultdto.Result {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	zero := 0
	x := &resultdto.BatchProcessReceipt{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: digest, OperationInputsSHA256: digest, InputClosureSHA256: digest, ToolSHA256: digest, Profile: "linux-static-fd-go127-poll/v1", ProfileSHA256: "sha256:48fd4c9ce6bbc9a748b01c7ee3f3bb57077d6f48768ef76ed123a6944bbbf132", ImplementationSHA256: digest, Launched: "yes", Disposition: "completed", ChildExitCode: &zero, Stdout: []byte{}, Stderr: []byte{}, StdoutSHA256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", StderrSHA256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", OutputComplete: true, Cleanup: "reaped"}
	env := resultdto.New(resultdto.OperationProjectRunBatch, "test")
	env.Project = &resultdto.Project{ID: "project.test", Root: "/public/project<>&"}
	if e := env.SetData(resultdto.BatchRunData{Phase: "executed", BatchReceipt: &resultdto.BatchReceipt{APIVersion: resultdto.BatchReceiptVersion, OperationInputsSHA256: digest, Disposition: "completed", Steps: []resultdto.BatchStepReceipt{{Ordinal: 0, Name: "inspect", RequestSHA256: digest, State: "observed", Receipt: x}}}}); e != nil {
		t.Fatal(e)
	}
	if _, e := decodeClosedBatchData(env.Data); e != nil {
		t.Fatal(e)
	}
	return env
}
func TestBatchSDKFactualSchemaAndFinalEquality(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	env := batchSDKFactualEnvelope(t)
	s.MCP().AddTool(mcp.NewTool("run_batch", outputSchema(resultdto.OperationProjectRunBatch)), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		call := ctx.Value(batchCallKey{}).(*batchCall)
		data := env
		mode := req.GetString("mode", "")
		switch mode {
		case "null-bytes":
			data.Data = bytes.ReplaceAll(data.Data, []byte(`"stdout":""`), []byte(`"stdout":null`))
		case "array-bytes":
			data.Data = bytes.ReplaceAll(data.Data, []byte(`"stdout":""`), []byte(`"stdout":[1,2]`))
		case "unknown-state":
			data.Data = bytes.ReplaceAll(data.Data, []byte(`"state":"observed"`), []byte(`"state":"invented"`))
		}
		out := structuredResult(data, false)
		if mode == "" || mode == "mismatch" {
			call.expected, _ = resultwire.Frame(call.layout.RequestID(), out)
			if mode == "mismatch" {
				call.expected = append(call.expected, ' ')
			}
		}
		return out, nil
	})
	h := batchHarness(t, s)
	id := `"<>&\"\n"`
	h.send(t, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"run_batch","arguments":{}}}`)
	actual := h.recv(t)
	var normalized any
	json.Unmarshal([]byte(id), &normalized)
	expected, _ := resultwire.Frame(mcp.NewRequestId(normalized), structuredResult(env, false))
	if !bytes.Equal(actual, expected) {
		t.Fatal("SDK factual bytes differ", string(actual))
	}
	for _, mode := range []string{"null-bytes", "array-bytes", "unknown-state", "mismatch"} {
		h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"run_batch","arguments":{"mode":%q}}}`, mode, mode))
		raw := h.recv(t)
		if mode == "mismatch" {
			if !bytes.Equal(raw, batchNullRefusal()) {
				t.Fatal("SDK equality guard bypassed")
			}
		} else if !bytes.Contains(raw, []byte(`"isError":true`)) || !bytes.Contains(raw, []byte("output schema validation failed")) {
			t.Fatal("SDK invalid output schema accepted", mode, string(raw))
		}
	}
	batchWait(t, func() bool { h.batch.mu.Lock(); defer h.batch.mu.Unlock(); return len(h.batch.active) == 0 })
}

// infiniteFrameTail never emits LF or EOF; an oversized reader must stop without
// asking this peer for the rest of its document or decoding its composite ID.
type infiniteFrameTail struct{ consumed int }

func (r *infiniteFrameTail) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.consumed += len(p)
	return len(p), nil
}
func TestBatchSharedFrameReaderExactLimitAndTerminalOverflow(t *testing.T) {
	for _, n := range []int{1, 4096, maxTransportInputFrame} {
		raw := strings.Repeat("x", n-1) + "\n"
		frame, e := readTransportFrame(context.Background(), bufio.NewReader(strings.NewReader(raw)))
		if e != nil || string(frame.raw) != raw || cap(frame.raw) > maxTransportInputFrame {
			t.Fatal("exact bounded frame changed", n, e)
		}
	}
	tail := &infiniteFrameTail{}
	frame, e := readTransportFrame(context.Background(), bufio.NewReader(tail))
	if !errors.Is(e, errTransportFrameLimit) || len(frame.raw) != 0 || tail.consumed > maxTransportInputFrame+4096 {
		t.Fatal("unbounded buffering/draining", tail.consumed, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tail = &infiniteFrameTail{}
	if _, e = readTransportFrame(ctx, bufio.NewReader(tail)); !errors.Is(e, context.Canceled) || tail.consumed != 0 {
		t.Fatal("cancelled input consumed", e)
	}
	frame, e = readTransportFrame(context.Background(), bufio.NewReader(strings.NewReader("ordinary EOF frame")))
	if !errors.Is(e, io.EOF) || string(frame.raw) != "ordinary EOF frame" {
		t.Fatal("ordinary final EOF bytes changed")
	}
	t.Logf("terminal overflow consumes at most %d bytes; raw retention <=%d", maxTransportInputFrame+4096, maxTransportInputFrame)
}
func TestBatchUpstreamOversizeBeforeDecodeAndNoWorker(t *testing.T) {
	for _, route := range []string{"run_batch", "graph_ast", "context_select", "ordinary"} {
		t.Run(route, func(t *testing.T) {
			s := New("/not-executable", "test", nil)
			defer s.Close()
			var calls atomic.Int32
			s.MCP().AddTool(mcp.NewTool(route), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				calls.Add(1)
				return mcp.NewToolResultText("unexpected"), nil
			})
			// The ID's arbitrary nested value would allocate during json.Unmarshal if
			// the earliest graph reader forwarded a partial oversized prefix.
			prefix := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + route + `"},"id":["`
			tail := &infiniteFrameTail{}
			var output bytes.Buffer
			g := newGraphTransport(context.Background(), s, io.MultiReader(strings.NewReader(prefix), tail), &output, nil)
			b := newBatchTransport(context.Background(), s, g)
			b.bindSession(context.Background())
			n, e := b.Read(make([]byte, 256))
			if n != 0 || !errors.Is(e, errTransportFrameLimit) {
				t.Fatal("oversized prefix forwarded", n, e)
			}
			if output.String() != string(graphNullRefusal()) || tail.consumed > maxTransportInputFrame+4096 || calls.Load() != 0 || len(g.active) != 0 || len(b.active) != 0 || g.ctx.Err() == nil {
				t.Fatal("oversize reached decoder/work or extra refusal", output.String(), tail.consumed)
			}
			b.close()
			g.close()
		})
	}
}
func TestBatchOwnOversizeRefusalIsTerminalAndBounded(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	var output bytes.Buffer
	g := newGraphTransport(context.Background(), s, strings.NewReader(""), &output, nil)
	b := newBatchTransport(context.Background(), s, g)
	tail := &infiniteFrameTail{}
	b.input = bufio.NewReader(tail)
	b.bindSession(context.Background())
	n, e := b.Read(make([]byte, 32))
	if n != 0 || !errors.Is(e, errTransportFrameLimit) || output.String() != string(batchNullRefusal()) || b.ctx.Err() == nil || g.ctx.Err() == nil {
		t.Fatal("batch overflow not terminal", e)
	}
	b.close()
	g.close()
}
func TestBatchSharedFrameForwardingBytesPreserved(t *testing.T) {
	raw := "{\"jsonrpc\":\"2.0\",\"method\":\"ordinary_alias\",\"id\":\"<&\\\"\"}\n" + "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":\"none\"}}\n"
	s := New("/not-executable", "test", nil)
	defer s.Close()
	var output bytes.Buffer
	g := newGraphTransport(context.Background(), s, strings.NewReader(raw), &output, nil)
	b := newBatchTransport(context.Background(), s, g)
	got, e := io.ReadAll(b)
	if e != nil || string(got) != raw || output.Len() != 0 {
		t.Fatal("ordinary/root/SDK bytes changed", e)
	}
	b.close()
	g.close()
}

func TestBatchOversizeRefusalBehindOrdinaryWriteIsFinite(t *testing.T) {
	s := New("/not-executable", "test", nil)
	defer s.Close()
	read, write, fill := graphFullPipe(t)
	defer read.Close()
	defer write.Close()
	tail := &infiniteFrameTail{}
	g := newGraphTransport(context.Background(), s, tail, write, write)
	b := newBatchTransport(context.Background(), s, g)
	b.bindSession(context.Background())
	holder := make(chan error, 1)
	go func() { _, e := g.Write([]byte("ordinary frame\n")); holder <- e }()
	batchWait(t, func() bool { return len(g.writeGate) == 1 })
	done := make(chan error, 1)
	go func() { _, e := b.Read(make([]byte, 256)); done <- e }()
	select {
	case e := <-done:
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal("wrong terminal refusal", e)
		}
	case <-time.After(time.Second):
		t.Fatal("oversize blocked behind unrelated frame")
	}
	if tail.consumed > maxTransportInputFrame+4096 || len(b.active) != 0 || len(g.active) != 0 || g.ctx.Err() == nil {
		t.Fatal("overflow retained work or drained peer")
	}
	select {
	case e := <-holder:
		t.Fatal("ordinary writer deadline changed", e)
	default:
	}
	if _, e := io.ReadFull(read, make([]byte, fill)); e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, len("ordinary frame\n"))
	if _, e := io.ReadFull(read, raw); e != nil || string(raw) != "ordinary frame\n" {
		t.Fatal("ordinary output changed", e)
	}
	if e := <-holder; e != nil {
		t.Fatal(e)
	}
	b.close()
	g.close()
}
