package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
)

func init() { dataSchemas[resultdto.OperationProjectRunBatch] = batchDataSchema }
func decodeClosedBatchData(raw []byte) (resultdto.BatchRunData, error) {
	return resultdto.DecodeBatchRunData(raw)
}

// batchDataSchema changes only the new operation's factual byte projections.
func batchDataSchema() (json.RawMessage, error) {
	raw, e := schemaOf[resultdto.BatchRunData]()
	if e != nil {
		return nil, e
	}
	var root map[string]any
	if e = json.Unmarshal(raw, &root); e != nil {
		return nil, e
	}
	batchSchemaWalk(root)
	props, ok := root["properties"].(map[string]any)
	if !ok {
		return nil, resultdto.ErrBatchData
	}
	props["phase"] = map[string]any{"type": "string", "enum": []any{"prepared", "executed"}}
	prepared := props["preparedRequests"].(map[string]any)
	prepared["type"] = "array"
	prepared["minItems"] = 1
	prepared["maxItems"] = resultdto.MaxBatchSteps
	receipt := props["batchReceipt"].(map[string]any)
	receipt["type"] = "object"
	rp := receipt["properties"].(map[string]any)
	rp["apiVersion"] = map[string]any{"const": resultdto.BatchReceiptVersion}
	rp["disposition"] = map[string]any{"enum": []any{"completed", "stopped", "recovery-required"}}
	steps := rp["steps"].(map[string]any)
	steps["type"] = "array"
	steps["minItems"] = 1
	steps["maxItems"] = resultdto.MaxBatchSteps

	root["required"] = []any{"phase"}
	root["additionalProperties"] = false
	root["oneOf"] = []any{
		map[string]any{"properties": map[string]any{"phase": map[string]any{"const": "prepared"}}, "required": []any{"preparedRequests"}, "not": map[string]any{"required": []any{"batchReceipt"}}},
		map[string]any{"properties": map[string]any{"phase": map[string]any{"const": "executed"}}, "required": []any{"batchReceipt"}, "not": map[string]any{"required": []any{"preparedRequests"}}},
	}
	return json.Marshal(root)
}
func batchSchemaWalk(node any) {
	switch n := node.(type) {
	case map[string]any:
		if props, ok := n["properties"].(map[string]any); ok {
			n["additionalProperties"] = false
			for key, value := range props {
				facet, ok := value.(map[string]any)
				if !ok {
					continue
				}
				if strings.HasSuffix(key, "SHA256") {
					facet["pattern"] = `^sha256:[a-f0-9]{64}$`
				}
				switch key {
				case "ordinal":
					facet["minimum"] = 0
					facet["maximum"] = 15
				case "state":
					facet["enum"] = []any{"unstarted", "attempted-unknown", "observed"}
				case "signal":
					facet["minimum"] = 0
					facet["maximum"] = 64
				case "stdoutBytes":
					facet["minimum"] = 0
					facet["maximum"] = resultdto.BatchStdoutLimit
				case "stderrBytes":
					facet["minimum"] = 0
					facet["maximum"] = resultdto.BatchStderrLimit
				case "childExitCode":
					facet["minimum"] = 0
					facet["maximum"] = 255
				case "persistentWrites":
					facet["const"] = 0
				case "timeoutMillis":
					facet["minimum"] = 1
					facet["maximum"] = 5000
				case "profile":
					facet["enum"] = []any{"darwin25G83-native-fd/v1", "linux-static-fd-go127/v1", "linux-static-fd-go127-poll/v1"}
				case "launched":
					facet["enum"] = []any{"yes", "no", "unknown"}
				case "cleanup":
					facet["enum"] = []any{"reaped", "pending", "failed"}
				}
			}
			if _, process := props["stdout"]; process {
				props["apiVersion"] = map[string]any{"const": "tplaiter.dev/action-receipt/v1"}
				props["disposition"] = map[string]any{"enum": []any{"completed", "refused", "indeterminate", "recovery-required"}}
			}

			for key := range props {
				if key == "stdout" || key == "stderr" {
					limit := resultdto.BatchStdoutLimit
					if key == "stderr" {
						limit = resultdto.BatchStderrLimit
					}
					props[key] = map[string]any{"type": "string", "contentEncoding": "base64", "maxLength": 4 * ((limit + 2) / 3), "pattern": `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`}
				}
			}
		}
		for _, v := range n {
			batchSchemaWalk(v)
		}
	case []any:
		for _, v := range n {
			batchSchemaWalk(v)
		}
	}
}

type batchCallKey struct{}
type batchCall struct {
	transport *batchTransport
	raw       json.RawMessage
	layout    resultwire.BatchFrameLayout
	ctx       context.Context
	cancel    context.CancelFunc
	sdkBound  bool
	child     *heldBatchChild
	expected  []byte
}
type batchTransport struct {
	server  *Server
	graph   *graphTransport
	input   *bufio.Reader
	pending []byte
	ctx     context.Context
	cancel  context.CancelFunc
	session context.Context
	mu      sync.Mutex
	active  map[string]*batchCall
	workers sync.WaitGroup
	closed  bool
}

func newBatchTransport(ctx context.Context, s *Server, g *graphTransport) *batchTransport {
	owned, cancel := context.WithCancel(ctx)
	return &batchTransport{server: s, graph: g, input: bufio.NewReader(g), ctx: owned, cancel: cancel, active: map[string]*batchCall{}}
}
func (b *batchTransport) bindSession(ctx context.Context) context.Context {
	b.session = ctx
	return b.graph.bindSession(ctx)
}
func (s *Server) installBatchHooks() {
	hooks := s.mcp.GetHooks()
	if hooks == nil {
		hooks = &server.Hooks{}
		server.WithHooks(hooks)(s.mcp)
	}
	hooks.AddOnRequestInitialization(func(ctx context.Context, id any, message any) error {
		call, ok := ctx.Value(batchCallKey{}).(*batchCall)
		if !ok {
			return nil
		}
		raw, ok := message.(json.RawMessage)
		encoded, e := json.Marshal(id)
		if !ok || e != nil || call.transport.server != s || !bytes.Equal(raw, call.raw) || !bytes.Equal(encoded, call.layout.ID) || call.ctx.Err() != nil {
			return resultwire.ErrBatchBinding
		}
		call.sdkBound = true
		return nil
	})
}
func batchNullRefusal() []byte {
	return []byte("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"BATCH_OUTPUT_BUDGET\"}}\n")
}
func (b *batchTransport) refuse() error {
	ctx, cancel := context.WithTimeout(b.ctx, 250*time.Millisecond)
	defer cancel()
	if e := b.graph.writeGraph(ctx, batchNullRefusal()); e != nil {
		b.stop()
		return e
	}
	return nil
}
func (b *batchTransport) stop() {
	b.cancel()
	b.graph.cancel()
	if b.graph.stopStdio != nil {
		b.graph.stopStdio()
	}
}
func (b *batchTransport) Read(p []byte) (int, error) {
	for len(b.pending) == 0 {
		frame, e := readTransportFrame(b.ctx, b.input)
		if e == errTransportFrameLimit {
			refusalError := b.refuse()
			b.stop()
			if refusalError != nil {
				return 0, refusalError
			}
			return 0, errTransportFrameHandled
		}
		line := frame.raw
		if len(line) == 0 {
			return 0, e
		}
		var notification struct {
			Method string `json:"method"`
			Params struct {
				RequestID any `json:"requestId"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &notification) == nil && notification.Method == "notifications/cancelled" {
			id, _ := json.Marshal(notification.Params.RequestID)
			b.mu.Lock()
			call := b.active[string(id)]
			b.mu.Unlock()
			if call != nil {
				call.cancel()
			}
		}
		var route struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
			Params  struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &route) != nil || route.Method != "tools/call" || route.Params.Name != "run_batch" {
			b.pending = line
			break
		}
		id, ie := json.Marshal(route.ID)
		layout := resultwire.BatchFrameLayout{APIVersion: resultwire.BatchFrameVersion, ID: id, Ceiling: resultdto.MaxBatchFrame}
		invalid := len(line) > 2<<20 || route.JSONRPC != "2.0" || ie != nil || layout.Validate() != nil || b.session == nil
		if !invalid {
			_, e = canonicaljson.Canonicalize(line)
			invalid = e != nil
		}
		if !invalid {
			frame, fe := resultwire.Frame(layout.RequestID(), mcp.NewToolResultError("BATCH_OUTPUT_BUDGET"))
			invalid = fe != nil || len(frame) > layout.Ceiling
		}
		if invalid {
			if e = b.refuse(); e != nil {
				return 0, e
			}
			continue
		}
		b.mu.Lock()
		if b.closed || len(b.active) >= 64 || b.active[string(id)] != nil {
			b.mu.Unlock()
			if e = b.refuse(); e != nil {
				return 0, e
			}
			continue
		}
		ctx, cancel := context.WithTimeout(b.session, b.server.timeout(longCall))
		stop := context.AfterFunc(b.ctx, cancel)
		call := &batchCall{transport: b, raw: append(json.RawMessage{}, line...), layout: layout, ctx: ctx, cancel: cancel}
		b.active[string(id)] = call
		b.workers.Add(1)
		b.mu.Unlock()
		go func() { defer stop(); b.dispatch(call) }()
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}
func (b *batchTransport) Write(raw []byte) (int, error) { return b.graph.Write(raw) }
func (b *batchTransport) dispatch(call *batchCall) {
	defer b.workers.Done()
	defer func() {
		call.cancel()
		if call.child != nil {
			call.child.close()
		}
		b.mu.Lock()
		if b.active[string(call.layout.ID)] == call {
			delete(b.active, string(call.layout.ID))
		}
		b.mu.Unlock()
	}()
	ctx := context.WithValue(call.ctx, batchCallKey{}, call)
	response := b.server.mcp.HandleMessage(ctx, call.raw)
	raw, e := json.Marshal(response)
	if e != nil || response == nil {
		raw = batchNullRefusal()
	} else {
		raw = append(raw, '\n')
	}
	valid := len(raw) <= call.layout.Ceiling && (len(call.expected) == 0 || bytes.Equal(raw, call.expected))
	if !valid {
		raw = batchNullRefusal()
	}
	if valid && call.child != nil {
		if e = call.child.exchangeBatch(1, "recheck", "ready"); e != nil {
			raw = batchNullRefusal()
			valid = false
		}
	}
	if e = b.graph.writeGraph(call.ctx, raw); e != nil {
		if !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
			b.stop()
		}
		return
	}
	if valid && call.child != nil {
		if e = call.child.exchangeBatch(2, "complete", "closed"); e != nil {
			call.cancel()
		}
	}
}
func (b *batchTransport) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	b.workers.Wait()
}

// callRunBatchDelivery accepts only a transport-owned SDK call. The child
// reconstructs authentic selection and performs its own pre-effect sizing.
func (s *Server) callRunBatchDelivery(ctx context.Context, req mcp.CallToolRequest, argv []string) (*mcp.CallToolResult, error) {
	call, ok := ctx.Value(batchCallKey{}).(*batchCall)
	if !ok || call == nil || !call.sdkBound || call.transport.server != s || req.Params.Name != "run_batch" {
		return mcp.NewToolResultError("BATCH_FRAME_BINDING_INVALID"), nil
	}
	// The backend owns argv creation. Arbitrary delivery controls cannot replace
	// the generated token/layout; flag collisions are rejected before launch.
	for _, arg := range argv {
		if strings.HasPrefix(arg, "--batch-delivery-token") || strings.HasPrefix(arg, "--batch-frame-layout") {
			return mcp.NewToolResultError("BATCH_FRAME_BINDING_INVALID"), nil
		}
	}
	cwd, err := resolveWorkDir(req.GetString("dir", "."))
	if err != nil {
		return s.argumentFailure(resultdto.OperationProjectRunBatch, "dir"), nil
	}
	child, env, err := s.startBatchDeliveryChild(call, cwd, withJSONFlag(argv))
	if err != nil {
		return mcp.NewToolResultError("BATCH_FRAME_BINDING_INVALID"), nil
	}
	call.child = child
	out := structuredResult(env, env.Status != resultdto.StatusOK)
	frame, err := resultwire.Frame(call.layout.RequestID(), out)
	if err != nil || len(frame) > call.layout.Ceiling {
		if child != nil {
			child.close()
		}
		call.child = nil
		return mcp.NewToolResultError("BATCH_OUTPUT_BUDGET"), nil
	}
	call.expected = frame
	return out, nil
}

// transportFrame is formed only after an incremental hard byte ceiling. No
// metadata decoder sees an oversized prefix or a partial refused frame.
type transportFrame struct{ raw []byte }

const maxTransportInputFrame = 2 << 20

var errTransportFrameLimit = errors.New("MCP_INPUT_FRAME_LIMIT")
var errTransportFrameHandled = errors.Join(errTransportFrameLimit, errors.New("MCP_INPUT_TERMINAL"))

func readTransportFrame(ctx context.Context, input *bufio.Reader) (transportFrame, error) {
	var raw []byte
	for {
		if err := ctx.Err(); err != nil {
			return transportFrame{}, err
		}
		part, err := input.ReadSlice('\n')
		if len(part) > maxTransportInputFrame-len(raw) {
			// Terminal overflow: retain neither prefix nor remainder. Resuming
			// after an unbounded drain would permit a newline-free peer to hold
			// the reader indefinitely. The caller sends one finite refusal and
			// cancels this transport; it never attempts another response.
			return transportFrame{}, errTransportFrameLimit
		}
		needed := len(raw) + len(part)
		if needed > cap(raw) {
			capacity := cap(raw) * 2
			if capacity < 4096 {
				capacity = 4096
			}
			if capacity < needed {
				capacity = needed
			}
			if capacity > maxTransportInputFrame {
				capacity = maxTransportInputFrame
			}
			next := make([]byte, len(raw), capacity)
			copy(next, raw)
			raw = next
		}
		raw = append(raw, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return transportFrame{}, err
		}
		if err := ctx.Err(); err != nil {
			return transportFrame{}, err
		}
		return transportFrame{raw: raw}, err
	}
}
