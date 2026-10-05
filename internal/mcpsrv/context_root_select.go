package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"golang.org/x/sys/unix"
)

const rootDeliveryVersion = "tplaiter.dev/root-delivery/v1"

type rootDeliveryMessage struct {
	APIVersion string `json:"apiVersion"`
	Token      string `json:"token"`
	Sequence   int    `json:"sequence"`
	Action     string `json:"action"`
	Digest     string `json:"digest"`
}

// Root records own request lifetime across the SDK's handler return. The SDK
// cancels its handler context before the stdio writer runs, so that context
// cannot own a lease intended to survive final response serialization.
type rootFrames struct {
	mu          sync.Mutex
	requests    map[string]*rootFrame
	meta        map[*mcp.Meta]*rootFrame
	queued      map[string]bool
	retired     map[string]*rootFrame
	retiredMeta map[*mcp.Meta]*rootFrame
}
type rootFrame struct {
	id       json.RawMessage
	raw      json.RawMessage
	ctx      context.Context
	cancel   context.CancelFunc
	child    *heldRootChild
	expected []byte
	ceiling  int
}

func (s *Server) installRootFrames() *rootFrames {
	f := &rootFrames{requests: make(map[string]*rootFrame), meta: make(map[*mcp.Meta]*rootFrame), queued: make(map[string]bool)}
	hooks := s.mcp.GetHooks()
	if hooks == nil {
		hooks = &server.Hooks{}
		server.WithHooks(hooks)(s.mcp)
	}
	hooks.AddOnRequestInitialization(func(ctx context.Context, id any, message any) error {
		raw, ok := message.(json.RawMessage)
		if !ok {
			return nil
		}
		var route struct {
			Method string `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Action string `json:"action"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &route) != nil || route.Method != "tools/call" || route.Params.Name != "context" || route.Params.Arguments.Action != "select" {
			return nil
		}
		encoded, _ := json.Marshal(id)
		admitted := false
		defer func() {
			if !admitted {
				f.mu.Lock()
				delete(f.queued, string(encoded))
				f.mu.Unlock()
			}
		}()
		if _, err := canonicaljson.Canonicalize(raw); err != nil {
			return errors.New(contextcmd.Invalid)
		}
		switch id.(type) {
		case string, float64:
		default:
			return errors.New(contextcmd.Invalid)
		}
		encoded, err := json.Marshal(id)
		if err != nil || id == nil || len(encoded) > 4096 {
			return errors.New(contextcmd.Invalid)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, exists := f.requests[string(encoded)]; exists || f.retired[string(encoded)] != nil || len(f.requests)+len(f.retired) >= 64 {
			return errors.New(contextcmd.Invalid)
		}
		owned, cancel := context.WithTimeout(ctx, s.timeout(shortCall))
		if f.queued[string(encoded)] {
			cancel()
		}
		delete(f.queued, string(encoded))
		record := &rootFrame{id: encoded, raw: raw, ctx: owned, cancel: cancel}
		f.requests[string(encoded)] = record
		context.AfterFunc(owned, func() { f.retire(record) })
		admitted = true
		return nil
	})
	// Installed after the local-preview hooks: this sees their final, server-owned
	// Meta pointer. Caller _meta values cannot manufacture a lookup key.
	hooks.AddBeforeCallTool(func(_ context.Context, id any, req *mcp.CallToolRequest) {
		if req.Params.Name != "context" || req.GetArguments()["action"] != "select" {
			return
		}
		encoded, err := json.Marshal(id)
		if err != nil {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		record := f.requests[string(encoded)]
		if record == nil {
			record = f.retired[string(encoded)]
		}
		if record != nil {
			f.meta[req.Params.Meta] = record
		}
	})
	// Decode errors retain the SDK's exact message allocation. Matching that
	// allocation, rather than its reusable ID or caller metadata, identifies
	// the request that actually acquired this slot.
	hooks.AddOnError(func(_ context.Context, id any, method mcp.MCPMethod, message any, err error) {
		if method != mcp.MethodToolsCall {
			return
		}
		var record *rootFrame
		var decode *server.UnparsableMessageError
		if errors.As(err, &decode) {
			raw := decode.GetMessage()
			encoded, _ := json.Marshal(id)
			f.mu.Lock()
			candidate := f.requests[string(encoded)]
			if candidate == nil {
				candidate = f.retired[string(encoded)]
			}
			if candidate != nil && len(raw) != 0 && len(raw) == len(candidate.raw) && &raw[0] == &candidate.raw[0] {
				record = candidate
			}
			f.mu.Unlock()
		} else if req, ok := message.(*mcp.CallToolRequest); ok && req.Params.Meta != nil {
			record = f.lookup(req.Params.Meta)
		}
		if record != nil {
			f.remove(record)
		}
	})
	hooks.AddAfterCallTool(func(_ context.Context, _ any, req *mcp.CallToolRequest, result any) {
		if req.Params.Name != "context" || req.GetArguments()["action"] != "select" {
			return
		}
		out, ok := result.(*mcp.CallToolResult)
		if !ok || out == nil {
			if record := f.lookup(req.Params.Meta); record != nil {
				f.remove(record)
			}
			return
		}
		record := f.lookup(req.Params.Meta)
		if out.IsError || (record != nil && record.ctx.Err() != nil) {
			if record := f.lookup(req.Params.Meta); record != nil {
				f.remove(record)
			}
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if record := f.meta[req.Params.Meta]; record != nil && record.child == nil {
			record.expected, _ = rootToolFrame(record.id, out)
		}
	})
	return f
}

func (f *rootFrames) lookup(meta *mcp.Meta) *rootFrame {
	f.mu.Lock()
	defer f.mu.Unlock()
	if record := f.meta[meta]; record != nil {
		return record
	}
	return f.retiredMeta[meta]
}

// Retired owners no longer occupy live request/meta tables. A bounded tombstone
// prevents ID reuse until that exact SDK request reaches its terminal hook or
// final writer, so a delayed old BeforeCallTool cannot bind a new owner's lease.
func (f *rootFrames) retire(record *rootFrame) {
	f.mu.Lock()
	if f.requests[string(record.id)] != record {
		f.mu.Unlock()
		return
	}
	delete(f.requests, string(record.id))
	if f.retired == nil {
		f.retired = make(map[string]*rootFrame)
	}
	f.retired[string(record.id)] = record
	if f.retiredMeta == nil {
		f.retiredMeta = make(map[*mcp.Meta]*rootFrame)
	}
	for meta, value := range f.meta {
		if value == record {
			f.retiredMeta[meta] = record
			delete(f.meta, meta)
		}
	}
	child := record.child
	f.mu.Unlock()
	if child != nil {
		child.close()
	}
}

func (f *rootFrames) remove(record *rootFrame) {
	f.mu.Lock()
	if f.requests[string(record.id)] == record {
		delete(f.requests, string(record.id))
	}
	if f.retired[string(record.id)] == record {
		delete(f.retired, string(record.id))
	}
	for meta, value := range f.meta {
		if value == record {
			delete(f.meta, meta)
		}
	}
	for meta, value := range f.retiredMeta {
		if value == record {
			delete(f.retiredMeta, meta)
		}
	}
	child := record.child
	f.mu.Unlock()
	record.cancel()
	if child != nil {
		child.close()
	}
}
func (f *rootFrames) close() {
	f.mu.Lock()
	clear(f.queued)
	records := make([]*rootFrame, 0, len(f.requests))
	for _, r := range f.requests {
		records = append(records, r)
	}
	for _, r := range f.retired {
		records = append(records, r)
	}
	f.mu.Unlock()
	for _, r := range records {
		f.remove(r)
	}
}

func rootToolFrame(id json.RawMessage, result *mcp.CallToolResult) ([]byte, error) {
	raw, err := json.Marshal(struct {
		JSONRPC string              `json:"jsonrpc"`
		ID      json.RawMessage     `json:"id"`
		Result  *mcp.CallToolResult `json:"result"`
	}{"2.0", id, result})
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// callRootSelection never accepts a caller executable, registration or runtime.
// All source admission happens in the fixed installed CLI's BeginRootSelection.
func (s *Server) callRootSelection(_ context.Context, req contextcmd.RootSelectionRequest, key, dir string, call mcp.CallToolRequest) *mcp.CallToolResult {
	record := s.rootFrames.lookup(call.Params.Meta)
	if record == nil {
		return s.argumentFailure(resultdto.OperationContextQuery, "rootSelection")
	}
	if req.MaxBytes == 0 {
		req.MaxBytes = 32768
	}
	if req.MaxRecords == 0 {
		req.MaxRecords = 256
	}
	if req.MaxBytes < 1 || req.MaxBytes > 32768 || req.MaxRecords < 1 || req.MaxRecords > 256 || len(req.Selections) < 1 || len(req.Selections) > 16 {
		return s.argumentFailure(resultdto.OperationContextQuery, "rootSelection")
	}
	raw, err := json.Marshal(req)
	if err != nil || len(raw) > 16384 {
		return s.argumentFailure(resultdto.OperationContextQuery, "rootSelection")
	}
	cwd := ""
	if dir != "" {
		var failure *mcp.CallToolResult
		cwd, failure = s.workDir(resultdto.OperationContextQuery, "dir", dir)
		if failure != nil {
			return failure
		}
	}
	argv := []string{"context", "select", "--request=" + string(raw), "--json"}
	if key != "" {
		argv = append(argv, "--project-context="+key)
	}
	if cwd != "" {
		argv = append(argv, "--dir="+cwd)
	}
	child, env, err := s.startRootChild(record.ctx, cwd, argv)
	if err != nil {
		return s.transportFailure(resultdto.OperationContextQuery, rootTransportCode(err), 0)
	}
	result := structuredResult(env, env.Status != resultdto.StatusOK)
	if child == nil {
		return result
	}
	encoded, err := rootToolFrame(record.id, result)
	if err != nil || len(encoded) > req.MaxBytes {
		child.close()
		return rootFailure(s, contextcmd.Budget)
	}
	// Publish only the exact complete frame. The writer checks these bytes again
	// after SDK schema validation and final serialization, before asking the
	// still-live child to recheck and before touching the output stream.
	s.rootFrames.mu.Lock()
	if record.ctx.Err() != nil || s.rootFrames.requests[string(record.id)] != record {
		s.rootFrames.mu.Unlock()
		child.close()
		return rootFailure(s, "MCP_CANCELLED")
	}
	record.child = child
	record.expected = encoded
	record.ceiling = req.MaxBytes
	s.rootFrames.mu.Unlock()
	return result
}

func rootFailure(s *Server, code string) *mcp.CallToolResult {
	env := resultdto.New(resultdto.OperationContextQuery, s.version)
	env.Status = resultdto.StatusBlocked
	env.Diagnostics = []resultdto.Diagnostic{{Code: code, Severity: "error", Message: "Complete ROOT context delivery was refused", Details: map[string]any{}}}
	return structuredResult(env, true)
}
func rootTransportCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "MCP_CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "MCP_TIMEOUT"
	}
	if errors.Is(err, errOutputLimit) {
		return "MCP_OUTPUT_LIMIT"
	}
	return "MCP_UNAVAILABLE"
}

type heldRootChild struct {
	ctx           context.Context
	cancel        context.CancelFunc
	control       *os.File
	replies       *os.File
	output        *io.PipeReader
	reader        *bufio.Reader
	token, digest string
	done          chan error
	once          sync.Once
}

func (s *Server) startRootChild(parent context.Context, cwd string, argv []string) (*heldRootChild, resultdto.Result, error) {
	empty := resultdto.Result{}
	if parent.Err() != nil {
		return nil, empty, parent.Err()
	}
	if !s.installed && !s.direct {
		return nil, empty, errTransportUnavailable
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, empty, errTransportUnavailable
	}
	s.children.Add(1)
	s.mu.Unlock()
	owned := false
	defer func() {
		if !owned {
			s.children.Done()
		}
	}()
	path := s.exe
	if s.installed {
		var err error
		path, err = s.stage.launchPath()
		if err != nil {
			return nil, empty, errTransportUnavailable
		}
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, empty, errTransportUnavailable
	}
	token := hex.EncodeToString(tokenBytes)
	input, control, err := os.Pipe()
	if err != nil {
		return nil, empty, err
	}
	replies, response, err := os.Pipe()
	if err != nil {
		input.Close()
		control.Close()
		return nil, empty, err
	}
	output, writer := io.Pipe()
	ctx, cancel := context.WithCancel(parent)
	child := &heldRootChild{ctx: ctx, cancel: cancel, control: control, replies: replies, output: output, reader: bufio.NewReaderSize(replies, 1025), token: token, done: make(chan error, 1)}
	cmd := exec.Command(path, append(argv, "--root-delivery-token="+token)...) //nolint:noctx,depguard // fixed held-stage path; RunGroup owns lifecycle
	cmd.Dir = cwd
	cmd.Env = s.childEnv
	cmd.ExtraFiles = []*os.File{input, response}
	cmd.Stdout = writer
	overflow := make(chan struct{}, 1)
	cmd.Stderr = newBoundedBuffer(maxToolStderr, overflow)
	owned = true
	go func() {
		_, err := execx.RunGroup(ctx, cmd, execx.GroupOptions{Grace: s.limits.KillGrace, Abort: overflow})
		input.Close()
		response.Close()
		writer.Close()
		child.done <- err
		close(child.done)
		s.children.Done()
	}()
	// A stopped child must unblock both reads, including a child that exited
	// before inherited pipe descriptors could be closed by its parent goroutine.
	stop := context.AfterFunc(ctx, func() { output.Close(); replies.Close(); control.Close() })
	_ = stop // The callback belongs to ctx; close always cancels it.
	stdout := bufio.NewReaderSize(output, 32769)
	frame, err := stdout.ReadSlice('\n')
	if err != nil || len(frame) > 32768 {
		child.close()
		if parent.Err() != nil {
			return nil, empty, parent.Err()
		}
		return nil, empty, errTransportUnavailable
	}
	env, err := resultdto.Decode(frame)
	if err != nil || env.Operation != resultdto.OperationContextQuery {
		child.close()
		return nil, empty, errTransportUnavailable
	}
	if env.Status != resultdto.StatusOK {
		child.close()
		return nil, env, nil
	}
	child.digest = evidencecas.Digest(frame)
	// Extra stdout is never a second response. Its first byte terminates the
	// closed protocol instead of allowing arbitrary child output to escape.
	go func() {
		if _, err := stdout.ReadByte(); err == nil {
			child.cancel()
		}
	}()
	return child, env, nil
}

func (c *heldRootChild) exchange(sequence int, action, want string) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(rootDeliveryMessage{rootDeliveryVersion, c.token, sequence, action, c.digest})
	if err != nil {
		return err
	}
	if err = writeRootBytes(c.control, append(raw, '\n')); err != nil {
		return err
	}
	line, err := c.reader.ReadSlice('\n')
	if err != nil || len(line) > 1024 {
		return errors.New(contextcmd.Stale)
	}
	var reply rootDeliveryMessage
	if canonicaljson.DecodeStrict(line, &reply) != nil || reply != (rootDeliveryMessage{rootDeliveryVersion, c.token, sequence, want, c.digest}) {
		return errors.New(contextcmd.Stale)
	}
	return c.ctx.Err()
}
func (c *heldRootChild) close() {
	c.once.Do(func() { c.cancel(); c.control.Close(); c.replies.Close(); c.output.Close(); <-c.done })
}

// rootResponseWriter receives the SDK's complete serialized frame. Neither an
// after-handler hook nor re-encoding an estimated frame releases a read lease.
type rootResponseWriter struct {
	frames *rootFrames
	server *Server
	out    io.Writer
	mu     sync.Mutex
}

func (w *rootResponseWriter) Write(frame []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(frame, &envelope) != nil || len(envelope.ID) == 0 {
		return w.out.Write(frame)
	}
	w.frames.mu.Lock()
	record := w.frames.requests[string(envelope.ID)]
	if record == nil {
		record = w.frames.retired[string(envelope.ID)]
	}
	w.frames.mu.Unlock()
	if record == nil {
		// Cancellation can retire the owner while the SDK finishes encoding.
		// An orphaned ROOT payload must never escape as a successful result.
		if isRootSelectionResult(envelope.Result) {
			replacement, err := rootToolFrame(envelope.ID, rootFailure(w.server, "MCP_CANCELLED"))
			if err != nil {
				return 0, err
			}
			if err = writeRootBytes(w.out, replacement); err != nil {
				return 0, err
			}
			return len(frame), nil
		}
		return w.out.Write(frame)
	}
	// A duplicate-ID protocol error has no result and must not consume the
	// original request's lease or alter another response's bytes.
	if len(envelope.Result) == 0 {
		return w.out.Write(frame)
	}
	// Correlation alone is not enough: a different tool may reply with the same
	// invalid reused ID. Preserve that frame and leave the ROOT request untouched.
	// This classifies output only; source authority remains exclusively in the
	// fixed installed child and its real retained RootSelection.
	if !bytes.Equal(frame, record.expected) && !isRootSelectionResult(envelope.Result) {
		return w.out.Write(frame)
	}
	defer w.frames.remove(record)
	if record.child == nil {
		return w.out.Write(frame)
	}
	refused := ""
	if !bytes.Equal(frame, record.expected) {
		refused = contextcmd.Stale
	} else if len(frame) > record.ceiling {
		refused = contextcmd.Budget
	} else if err := record.child.exchange(1, "recheck", "ready"); err != nil {
		refused = contextcmd.Stale
		if record.ctx.Err() != nil {
			refused = rootTransportCode(record.ctx.Err())
		}
	}
	if refused != "" {
		replacement, err := rootToolFrame(record.id, rootFailure(w.server, refused))
		if err != nil {
			return 0, err
		}
		if err = writeRootBytes(w.out, replacement); err != nil {
			return 0, err
		}
		return len(frame), nil
	}
	// Pipe deadlines interrupt a cancelled blocked ROOT write. Reset before
	// another frame can enter; unrelated tools keep their original deadlines.
	if file, ok := w.out.(*os.File); ok {
		deadline, _ := record.ctx.Deadline()
		if err := file.SetWriteDeadline(deadline); err != nil {
			info, statErr := file.Stat()
			if statErr != nil || !info.Mode().IsRegular() {
				return 0, err
			}
		} else {
			finished := make(chan struct{})
			stop := context.AfterFunc(record.ctx, func() { defer close(finished); _ = file.SetWriteDeadline(time.Now()) })
			defer func() {
				if !stop() {
					<-finished
				}
				_ = file.SetWriteDeadline(time.Time{})
			}()
		}
	}
	if err := writeRootBytes(w.out, frame); err != nil {
		return 0, err
	}
	if err := record.child.exchange(2, "complete", "closed"); err != nil {
		return len(frame), err
	}
	return len(frame), nil
}
func writeRootBytes(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

// Observe cancellation notifications without modifying bytes passed to the
// SDK. This also covers cancellation after the SDK removed its handler entry.
type rootCancellationReader struct {
	in      io.Reader
	frames  *rootFrames
	pending []byte
}

func (r *rootCancellationReader) Read(p []byte) (int, error) {
	n, err := r.in.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			var notification struct {
				Method string `json:"method"`
				Params struct {
					RequestID any `json:"requestId"`
				} `json:"params"`
			}
			var route struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
				Params struct {
					Name      string `json:"name"`
					Arguments struct {
						Action string `json:"action"`
					} `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(r.pending, &route) == nil && route.Method == "tools/call" && route.Params.Name == "context" && route.Params.Arguments.Action == "select" && route.ID != nil {
				id, _ := json.Marshal(route.ID)
				r.frames.mu.Lock()
				if r.frames.requests[string(id)] == nil && len(r.frames.queued) < 64 && len(id) <= 4096 {
					if _, exists := r.frames.queued[string(id)]; !exists {
						r.frames.queued[string(id)] = false
					}
				}
				r.frames.mu.Unlock()
			}
			if json.Unmarshal(r.pending, &notification) == nil && notification.Method == "notifications/cancelled" && notification.Params.RequestID != nil {
				id, _ := json.Marshal(notification.Params.RequestID)
				r.frames.mu.Lock()
				record := r.frames.requests[string(id)]
				if _, exists := r.frames.queued[string(id)]; exists {
					r.frames.queued[string(id)] = true
				}
				r.frames.mu.Unlock()
				if record != nil {
					record.cancel()
				}
			}
			r.pending = nil
		} else if len(r.pending) <= 65536 {
			r.pending = append(r.pending, b)
		}
	}
	return n, err
}

func isRootSelectionResult(raw json.RawMessage) bool {
	// Payload presence selects stricter refusal handling, never grants authority.
	// Even a removed or invalid version must not bypass the exact-frame check.
	var result struct {
		StructuredContent struct {
			Operation resultdto.Operation        `json:"operation"`
			Data      map[string]json.RawMessage `json:"data"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(raw, &result) != nil || result.StructuredContent.Operation != resultdto.OperationContextQuery {
		return false
	}
	_, root := result.StructuredContent.Data["nativeRootSelection"]
	_, body := result.StructuredContent.Data["body"]
	var action string
	_ = json.Unmarshal(result.StructuredContent.Data["action"], &action)
	return root || body || action == "select"
}

// Go's inherited Stdout is not pollable. Duplicate the fixed descriptor and
// register that duplicate after setting nonblocking mode. All SDK writes use
// this one transport-owned writer; no request chooses a descriptor or endpoint.
// Closing restores the original descriptor mode before releasing the duplicate. ROOT deadlines
// apply only during its serialized write and are cleared before other frames.
func rootStdioOutput() (*os.File, func(), error) {
	fd, err := syscall.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return nil, nil, err
	}
	syscall.CloseOnExec(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), "tplaiter-mcp-output")
	closeOutput := func() { _ = syscall.SetNonblock(fd, flags&syscall.O_NONBLOCK != 0); _ = file.Close() }
	return file, closeOutput, nil
}
