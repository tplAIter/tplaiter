package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// Pipe peers below test transport ordering only. They do not impersonate
// authenticated installed source admission; the normal-install suite does that.
func rootB2PipeChild(t *testing.T, ctx context.Context, bad bool) (*heldRootChild, <-chan string) {
	t.Helper()
	input, control, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	replies, response, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	output, writer := io.Pipe()
	owned, cancel := context.WithCancel(ctx)
	c := &heldRootChild{ctx: owned, cancel: cancel, control: control, replies: replies, output: output, reader: bufio.NewReaderSize(replies, 1025), token: strings.Repeat("ab", 32), digest: evidencecas.Digest([]byte("actual-child-frame\n")), done: make(chan error, 1)}
	events := make(chan string, 4)
	go func() {
		defer input.Close()
		defer response.Close()
		defer writer.Close()
		defer close(c.done)
		defer close(events)
		dec := json.NewDecoder(input)
		for sequence, action := range []string{"recheck", "complete"} {
			var message rootDeliveryMessage
			if e := dec.Decode(&message); e != nil {
				return
			}
			if message.Sequence != sequence+1 || message.Action != action || message.Token != c.token || message.Digest != c.digest {
				c.done <- errors.New("bad control")
				return
			}
			events <- action
			reply := message
			reply.Action = "ready"
			if action == "complete" {
				reply.Action = "closed"
			}
			if bad {
				reply.Digest = evidencecas.Digest(nil)
			}
			b, _ := json.Marshal(reply)
			if _, e := response.Write(append(b, '\n')); e != nil {
				return
			}
		}
	}()
	t.Cleanup(c.close)
	return c, events
}
func rootB2Record(t *testing.T, s *Server, id string, result *mcp.CallToolResult, bad bool) (*rootFrame, <-chan string) {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(id), &value); err != nil {
		t.Fatal(err)
	}
	canonicalID, _ := json.Marshal(value)
	id = string(canonicalID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	child, events := rootB2PipeChild(t, ctx, bad)
	record := &rootFrame{id: json.RawMessage(id), ctx: ctx, cancel: cancel, child: child, ceiling: 32768}
	record.expected, _ = rootToolFrame(record.id, result)
	s.rootFrames.mu.Lock()
	s.rootFrames.requests[id] = record
	s.rootFrames.mu.Unlock()
	t.Cleanup(func() { s.rootFrames.remove(record) })
	return record, events
}

type rootB2OrderWriter struct {
	t      *testing.T
	events <-chan string
	ctx    context.Context
	body   bytes.Buffer
	broken bool
}

func (w *rootB2OrderWriter) Write(b []byte) (int, error) {
	w.t.Helper()
	select {
	case event := <-w.events:
		if event != "recheck" {
			w.t.Fatal("output preceded recheck", event)
		}
	default:
		w.t.Fatal("output preceded ready handshake")
	}
	if w.ctx.Err() != nil {
		w.t.Fatal("delivery lifetime ended before write")
	}
	if w.broken {
		return 0, io.ErrClosedPipe
	}
	return w.body.Write(b)
}

func TestRootB2MCPCompleteFrameAndHeldWrite(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	env := resultdto.New(resultdto.OperationContextQuery, "test")
	env.Project = &resultdto.Project{ID: "root", Root: "/public/<path>&\\escaped"}
	if e := env.SetData(resultdto.ContextRootSelectionData{Body: resultdto.RootContextBody{Files: []resultdto.RootContextFile{{Content: []byte{0, 255, 10, '<', '&', '"'}}}}}); e != nil {
		t.Fatal(e)
	}
	result := structuredResult(env, false)
	id := `"<request>&\\id"`
	frame, e := rootToolFrame(json.RawMessage(id), result)
	if e != nil {
		t.Fatal(e)
	}
	if frame[len(frame)-1] != '\n' || !bytes.Contains(frame, []byte(`\u003c`)) || !bytes.Contains(frame, []byte("data: see structured content")) {
		t.Fatal("complete outer ID/summary/escaping absent")
	}
	record, events := rootB2Record(t, s, id, result, false)
	record.ceiling = len(frame)
	out := &rootB2OrderWriter{t: t, events: events, ctx: record.ctx}
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: out}
	if n, e := w.Write(frame); e != nil || n != len(frame) {
		t.Fatal(n, e)
	}
	if !bytes.Equal(out.body.Bytes(), frame) {
		t.Fatal("writer changed complete frame")
	}
	if event := <-events; event != "complete" {
		t.Fatal("child released before complete write", event)
	}
	if record.ctx.Err() == nil {
		t.Fatal("delivery lifetime leaked")
	}
	if len(s.rootFrames.requests) != 0 {
		t.Fatal("correlation leaked")
	}
	t.Logf("complete MCP frame=%d incl ID/summary/base64/escaping/newline; ready -> write -> complete -> close", len(frame))
	// Boundary-minus-one refuses the whole result before the recheck or output.
	record, events = rootB2Record(t, s, id, result, false)
	record.ceiling = len(frame) - 1
	var refused bytes.Buffer
	w.out = &refused
	if _, e = w.Write(frame); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(refused.Bytes(), []byte(`"body"`)) || !bytes.Contains(refused.Bytes(), []byte(contextcmd.Budget)) {
		t.Fatal("over-budget body escaped")
	}
	if _, ok := <-events; ok {
		t.Fatal("over-budget reached control channel")
	}
}

func TestRootB2MCPStaleCancelledBrokenPipeAndUnrelatedFrames(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	result := structuredResult(resultdto.New(resultdto.OperationContextQuery, "test"), false)
	record, events := rootB2Record(t, s, `"stale"`, result, true)
	var out bytes.Buffer
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	if _, e := w.Write(record.expected); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out.Bytes(), []byte(contextcmd.Stale)) {
		t.Fatal("bad pin-bound recheck reply accepted")
	}
	<-events
	record, events = rootB2Record(t, s, `"broken"`, result, false)
	w.out = &rootB2OrderWriter{t: t, events: events, ctx: record.ctx, broken: true}
	if _, e := w.Write(record.expected); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("broken writer accepted", e)
	}
	if record.ctx.Err() == nil {
		t.Fatal("broken writer leaked child")
	}
	record, _ = rootB2Record(t, s, `"cancelled"`, result, false)
	record.cancel()
	out.Reset()
	w.out = &out
	if _, e := w.Write(record.expected); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out.Bytes(), []byte("MCP_CANCELLED")) {
		t.Fatal("cancelled body emitted")
	}
	record, _ = rootB2Record(t, s, `"same-id"`, result, false)
	unrelated := []byte(`{"jsonrpc":"2.0","id":"same-id","result":{"structuredContent":{"operation":"project.diff","data":{"files":[]}}}}` + "\n")
	out.Reset()
	w.out = &out
	if _, e := w.Write(unrelated); e != nil || !bytes.Equal(out.Bytes(), unrelated) || record.ctx.Err() != nil {
		t.Fatal("unrelated same-ID frame consumed ROOT lease or changed bytes")
	}
	s.rootFrames.remove(record)
	for _, raw := range []string{`{"jsonrpc":"2.0","id":42,"result":{"unrelated":true}}` + "\n", `{"jsonrpc":"2.0","method":"notifications/message","params":{"text":"<>&"}}` + "\n"} {
		out.Reset()
		if _, e := w.Write([]byte(raw)); e != nil || out.String() != raw {
			t.Fatal("unrelated frame changed")
		}
	}
}

func TestRootB2SDKHandlerReturnIsNotDeliveryCompletion(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	var handlerCtx context.Context
	var record *rootFrame
	s.mcp.AddTool(mcp.NewTool("context"), func(ctx context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCtx = ctx
		record = s.rootFrames.lookup(call.Params.Meta)
		return mcp.NewToolResultText("test ordering only"), nil
	})
	response := s.mcp.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":"held","method":"tools/call","params":{"name":"context","arguments":{"action":"select"}}}`))
	if response == nil || record == nil {
		t.Fatal("server-owned ROOT correlation absent")
	}
	if handlerCtx.Err() == nil || record.ctx.Err() != nil {
		t.Fatal("SDK handler lifetime confused with final byte delivery")
	}
	raw, _ := json.Marshal(response)
	var out bytes.Buffer
	writer := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	if _, e := writer.Write(append(raw, '\n')); e != nil {
		t.Fatal(e)
	}
	if record.ctx.Err() == nil {
		t.Fatal("final writer did not close correlation")
	}
}

func TestRootB2CancellationAfterHandlerAndConcurrentCorrelation(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	result := mcp.NewToolResultText("readonly transport fixture")
	first, _ := rootB2Record(t, s, `"one"`, result, false)
	second, _ := rootB2Record(t, s, `"two"`, result, false)
	input := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"one"}}` + "\n")
	observed := &rootCancellationReader{in: bytes.NewReader(input), frames: s.rootFrames}
	var forwarded bytes.Buffer
	buffer := make([]byte, 3)
	for {
		n, e := observed.Read(buffer)
		forwarded.Write(buffer[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(input, forwarded.Bytes()) || first.ctx.Err() == nil || second.ctx.Err() != nil {
		t.Fatal("cancellation altered bytes or another request")
	}
	s.rootFrames.remove(first)
	var out bytes.Buffer
	writer := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	// Independent requests may finish concurrently; the writer serializes complete
	// frames and each completion addresses only its own live pipe child.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf(`"parallel-%d"`, i)
		record, _ := rootB2Record(t, s, id, result, false)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := writer.Write(record.expected); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if second.ctx.Err() != nil {
		t.Fatal("other request cancelled by concurrent cleanup")
	}
	s.rootFrames.remove(second)
	if len(s.rootFrames.requests) != 0 {
		t.Fatal("child/correlation cleanup incomplete")
	}
}

func TestRootB2RawOther29Descriptors(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	tools := s.mcp.ListTools()
	if len(tools) != 30 {
		t.Fatal("tool inventory changed")
	}
	names := []string{}
	for name := range tools {
		if name != "context" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	raw := map[string]json.RawMessage{}
	for _, name := range names {
		b, e := json.Marshal(tools[name].Tool)
		if e != nil {
			t.Fatal(e)
		}
		raw[name] = b
	}
	if len(raw) != 29 || raw["project_link"] == nil {
		t.Fatal("other 29 inventory lost")
	}
	if path := os.Getenv("TPLAITER_ROOT_OTHER29_EXPORT"); path != "" {
		b, _ := json.Marshal(raw)
		if e := os.WriteFile(path, append(b, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Log("all 29 unrelated descriptors captured, including project_link")
}

func TestRootB2BlockedWriteCancellationAndDeadlineReset(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	result := mcp.NewToolResultText(strings.Repeat("complete", 20000))
	record, _ := rootB2Record(t, s, `"blocked"`, result, false)
	record.ceiling = len(record.expected)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: write}
	done := make(chan error, 1)
	go func() { _, err := w.Write(record.expected); done <- err }()
	// The pipe is smaller than the complete frame, so the write cannot finish
	// while its reader remains idle. Cancellation must interrupt and reap it.
	time.Sleep(20 * time.Millisecond)
	record.cancel()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("blocked cancelled write succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked writer did not terminate")
	}
	if record.ctx.Err() == nil || len(s.rootFrames.requests) != 0 {
		t.Fatal("cancelled blocked frame leaked lifetime")
	}
	// Drain any already-written prefix; a broken/partial response cannot be rolled
	// back. No success receipt or second frame is appended to repair that prefix.
	if err = read.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 262144)
	_, _ = read.Read(buffer)
	_ = read.SetReadDeadline(time.Time{})
	next := []byte(`{"jsonrpc":"2.0","id":9,"result":{}}` + "\n")
	completed := make(chan error, 1)
	go func() { _, e := w.Write(next); completed <- e }()
	select {
	case err = <-completed:
		if err != nil {
			t.Fatal("ROOT deadline affected next tool frame", err)
		}
	case <-time.After(time.Second):
		t.Fatal("next frame blocked")
	}
	got := make([]byte, len(next))
	if _, err = io.ReadFull(read, got); err != nil || !bytes.Equal(got, next) {
		t.Fatal("next frame bytes changed", err)
	}
}

func TestRootB2InheritedOutputDeadlineAndModeRestoration(t *testing.T) {
	flags, err := unix.FcntlInt(os.Stdout.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, closeOutput, err := rootStdioOutput()
	if err != nil {
		t.Fatal(err)
	}
	if err = out.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		closeOutput()
		t.Fatal("inherited pipe duplicate is not pollable", err)
	}
	_ = out.SetWriteDeadline(time.Time{})
	fdFlags, err := unix.FcntlInt(out.Fd(), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		closeOutput()
		t.Fatal("output duplicate leaks into children", err)
	}
	closeOutput()
	after, err := unix.FcntlInt(os.Stdout.Fd(), unix.F_GETFL, 0)
	if err != nil || flags != after {
		t.Fatal("original descriptor flags changed", err)
	}
}
func TestRootB2RejectsRawDuplicatesBeforeHandler(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	called := false
	s.mcp.AddTool(mcp.NewTool("context"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called = true
		return mcp.NewToolResultText("not authentication"), nil
	})
	raw := json.RawMessage(`{"jsonrpc":"2.0","id":"raw","method":"tools/call","params":{"name":"context","arguments":{"action":"select","rootSelection":{"maxBytes":1,"maxBytes":2}}}}`)
	response := s.mcp.HandleMessage(context.Background(), raw)
	if response == nil || called || len(s.rootFrames.requests) != 0 {
		t.Fatal("duplicate raw fields normalized before ROOT validation")
	}
}

func TestRootB2CorruptedRootPayloadCannotBypassFinalWriter(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	env := resultdto.New(resultdto.OperationContextQuery, "test")
	root := resultdto.ContextRootSelectionData{Body: resultdto.RootContextBody{APIVersion: "tplaiter.dev/context-root-selection/v1", Files: []resultdto.RootContextFile{{Content: []byte("mandatory image")}}}}
	if err := env.SetData(resultdto.ContextData{Action: "select", NativeRootSelection: &root}); err != nil {
		t.Fatal(err)
	}
	result := structuredResult(env, false)
	record, events := rootB2Record(t, s, `"corrupt-version"`, result, false)
	changed := bytes.Replace(record.expected, []byte("tplaiter.dev/context-root-selection/v1"), []byte("invalid-version"), 1)
	var out bytes.Buffer
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	if _, err := w.Write(changed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("mandatory image")) || bytes.Contains(out.Bytes(), []byte(`"nativeRootSelection"`)) || !bytes.Contains(out.Bytes(), []byte(contextcmd.Stale)) {
		t.Fatal("corrupted ROOT version bypassed held final write")
	}
	if _, ok := <-events; ok {
		t.Fatal("corrupt serialized body reached held child")
	}
}
func TestRootB2QueuedCancellationAndMalformedCleanup(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	raw := []byte(`{"jsonrpc":"2.0","id":"queued","method":"tools/call","params":{"name":"context","arguments":{"action":"select","rootSelection":{}}}}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"queued"}}` + "\n")
	reader := &rootCancellationReader{in: bytes.NewReader(raw), frames: s.rootFrames}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	var record *rootFrame
	s.mcp.AddTool(mcp.NewTool("context"), func(_ context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		record = s.rootFrames.lookup(call.Params.Meta)
		return mcp.NewToolResultError("cancel counter only"), nil
	})
	response := s.mcp.HandleMessage(context.Background(), json.RawMessage(bytes.Split(raw, []byte("\n"))[0]))
	if (record != nil && record.ctx.Err() == nil) || len(s.rootFrames.queued) != 0 {
		t.Fatal("queued cancellation lost before handler")
	}
	encoded, _ := json.Marshal(response)
	var out bytes.Buffer
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	duplicate := []byte(`{"jsonrpc":"2.0","id":"bad","method":"tools/call","params":{"name":"context","arguments":{"action":"select","rootSelection":{"maxBytes":1,"maxBytes":2}}}}` + "\n")
	reader = &rootCancellationReader{in: bytes.NewReader(duplicate), frames: s.rootFrames}
	io.Copy(io.Discard, reader)
	_ = s.mcp.HandleMessage(context.Background(), json.RawMessage(bytes.TrimSpace(duplicate)))
	if len(s.rootFrames.queued) != 0 || len(s.rootFrames.requests) != 0 {
		t.Fatal("malformed queued ROOT request leaked correlation")
	}
}

func TestRootB2MalformedSDKRequestCorrelationRecovery(t *testing.T) {
	s := New("/nonexistent", "independent-counter", nil)
	defer s.rootFrames.close()
	called := 0
	s.mcp.AddTool(mcp.NewTool("context"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		called++
		return mcp.NewToolResultText("ordering-only; no source admission"), nil
	})
	var output bytes.Buffer
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: &output}
	for i := 0; i < 64; i++ {
		raw := json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":"malformed-%d","method":"tools/call","params":{"name":"context","arguments":{"action":"select"},"_meta":1}}`, i))
		response := s.mcp.HandleMessage(context.Background(), raw)
		b, e := json.Marshal(response)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Contains(b, []byte(`"error"`)) {
			t.Fatal("counter did not reach SDK request decode refusal")
		}
		if _, e = w.Write(append(b, '\n')); e != nil {
			t.Fatal(e)
		}
	}
	retained := len(s.rootFrames.requests)
	response := s.mcp.HandleMessage(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":"valid-after-errors","method":"tools/call","params":{"name":"context","arguments":{"action":"select"}}}`))
	b, _ := json.Marshal(response)
	t.Logf("64 SDK error frames delivered; retained ROOT records=%d; next valid handler calls=%d; response=%s", retained, called, b)
	if retained != 0 || called != 1 {
		t.Fatalf("ROOT error-response cleanup absent: retained=%d handlerCalls=%d", retained, called)
	}
}

func TestRootB2SDKTerminalsPreserveDuplicateOwner(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	defer s.rootFrames.close()
	result := structuredResult(resultdto.New(resultdto.OperationContextQuery, "test"), false)
	active, events := rootB2Record(t, s, `"held"`, result, false)
	var out bytes.Buffer
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: &out}
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":"held","method":"tools/call","params":{"name":"context","arguments":{"action":"select"},"_meta":1}}`,
		`{"jsonrpc":"2.0","id":"held","method":"tools/call","params":{"name":"unrelated","arguments":{},"_meta":1}}`,
		`{"jsonrpc":"2.0","id":"held","method":"tools/call","params":{"name":"context","arguments":{"action":"select"}}}`,
	} {
		response := s.mcp.HandleMessage(context.Background(), json.RawMessage(raw))
		frame, _ := json.Marshal(response)
		if !bytes.Contains(frame, []byte(`"error"`)) {
			t.Fatal("control did not reach protocol error")
		}
		if _, err := w.Write(append(frame, '\n')); err != nil {
			t.Fatal(err)
		}
		s.rootFrames.mu.Lock()
		retained := s.rootFrames.requests[`"held"`] == active
		s.rootFrames.mu.Unlock()
		if !retained || active.ctx.Err() != nil {
			t.Fatal("unrelated or duplicate ID error consumed original lease")
		}
	}
	if _, err := w.Write(active.expected); err != nil {
		t.Fatal(err)
	}
	if <-events != "recheck" || <-events != "complete" {
		t.Fatal("original delivery did not complete")
	}
	for _, terminal := range []string{"handler", "validation", "schema", "cancel", "timeout"} {
		t.Run(terminal, func(t *testing.T) {
			var owned *rootFrame
			tool := mcp.NewTool("context")
			if terminal == "validation" {
				tool = mcp.NewTool("context", mcp.WithString("mandatory", mcp.Required()))
			}
			if terminal == "schema" {
				tool = mcp.NewTool("context", mcp.WithRawOutputSchema(json.RawMessage(`{"type":"object","required":["mandatory"]}`)))
			}
			s.mcp.AddTool(tool, func(_ context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				owned = s.rootFrames.lookup(call.Params.Meta)
				if owned == nil {
					t.Fatal("handler has no owned request")
				}
				switch terminal {
				case "handler":
					return nil, errors.New("owned handler counter")
				case "cancel":
					owned.cancel()
					s.rootFrames.retire(owned)
				case "timeout":
					<-owned.ctx.Done()
					s.rootFrames.retire(owned)
				}
				return &mcp.CallToolResult{StructuredContent: map[string]any{}}, nil
			})
			ctx := context.Background()
			if terminal == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			raw := json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"context","arguments":{"action":"select"}}}`, terminal))
			response := s.mcp.HandleMessage(ctx, raw)
			frame, _ := json.Marshal(response)
			if _, err := w.Write(append(frame, '\n')); err != nil {
				t.Fatal(err)
			}
			limit := time.Now().Add(time.Second)
			for {
				s.rootFrames.mu.Lock()
				n := len(s.rootFrames.requests)
				m := len(s.rootFrames.meta) + len(s.rootFrames.retiredMeta)
				r := len(s.rootFrames.retired)
				s.rootFrames.mu.Unlock()
				if n == 0 && m == 0 && r == 0 {
					break
				}
				if time.Now().After(limit) {
					t.Fatalf("%s terminal leaked requests=%d meta=%d", terminal, n, m)
				}
				time.Sleep(time.Millisecond)
			}
			if terminal == "validation" {
				return
			}
			if owned.ctx.Err() == nil {
				t.Fatal("terminal retained live lifetime")
			}
		})
	}
	t.Log("SDK decode, handler, output-schema, cancellation and deadline terminals release owned slots; duplicate-ID/unrelated errors preserve original held delivery")
}

func TestRootB2CancelledBeforeDecodeCannotRebindReusedID(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	defer s.rootFrames.close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.mcp.GetHooks().AddOnRequestInitialization(func(_ context.Context, _ any, _ any) error { once.Do(func() { close(entered); <-release }); return nil })
	calls := 0
	var owners []*rootFrame
	s.mcp.AddTool(mcp.NewTool("context"), func(_ context.Context, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls++
		owned := s.rootFrames.lookup(call.Params.Meta)
		owners = append(owners, owned)
		if owned == nil {
			t.Error("request lost exact owner")
		}
		return mcp.NewToolResultError("source-free ordering counter"), nil
	})
	raw := json.RawMessage(`{"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"context","arguments":{"action":"select"}}}`)
	done := make(chan any, 1)
	go func() { done <- s.mcp.HandleMessage(context.Background(), raw) }()
	<-entered
	s.rootFrames.mu.Lock()
	original := s.rootFrames.requests[`"reuse"`]
	s.rootFrames.mu.Unlock()
	original.cancel()
	s.rootFrames.retire(original)
	// Even byte-identical reused input has a different allocation and cannot
	// acquire a slot while the old SDK decode/terminal remains outstanding.
	response := s.mcp.HandleMessage(context.Background(), append(json.RawMessage(nil), raw...))
	frame, _ := json.Marshal(response)
	if !bytes.Contains(frame, []byte(`"error"`)) {
		t.Fatal("cancelled outstanding owner allowed ID reuse")
	}
	close(release)
	<-done
	if calls != 1 || owners[0] != original || original.ctx.Err() == nil {
		t.Fatal("old SDK handler rebound a replacement lease")
	}
	s.rootFrames.mu.Lock()
	n := len(s.rootFrames.requests) + len(s.rootFrames.retired) + len(s.rootFrames.meta) + len(s.rootFrames.retiredMeta)
	s.rootFrames.mu.Unlock()
	if n != 0 {
		t.Fatal("cancelled terminal retained correlation", n)
	}
	_ = s.mcp.HandleMessage(context.Background(), append(json.RawMessage(nil), raw...))
	if calls != 2 || owners[1] == original || owners[1] == nil {
		t.Fatal("terminal failed to permit a fresh independent owner")
	}
	t.Log("cancel-before-decode preserves exact old owner, rejects overlap, clears terminal, then permits fresh ID reuse")
}

func TestRootB2RegularFileFinalDelivery(t *testing.T) {
	s := New("/nonexistent", "test", nil)
	defer s.rootFrames.close()
	result := structuredResult(resultdto.New(resultdto.OperationContextQuery, "test"), false)
	record, events := rootB2Record(t, s, `"file"`, result, false)
	output, err := os.CreateTemp(t.TempDir(), "response")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	w := &rootResponseWriter{frames: s.rootFrames, server: s, out: output}
	if _, err = w.Write(record.expected); err != nil {
		t.Fatal(err)
	}
	if <-events != "recheck" || <-events != "complete" {
		t.Fatal("regular-file delivery failed held protocol")
	}
	raw, err := os.ReadFile(output.Name())
	if err != nil || !bytes.Equal(raw, record.expected) {
		t.Fatal("regular-file final bytes changed", err)
	}
}
