package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

func init() {
	for _, op := range []resultdto.Operation{resultdto.OperationGraphSource, resultdto.OperationGraphExports, resultdto.OperationGraphAST, resultdto.OperationGraphStats} {
		dataSchemas[op] = graphDataSchema
	}
}

// graphDataSchema corrects only native RawMessage scalar parameters. The SDK
// reflector treats RawMessage as bytes; the native wire carries JSON scalars.
func graphDataSchema() (json.RawMessage, error) {
	raw, err := schemaOf[resultdto.GraphData]()
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	if err = json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	for _, keys := range [][]string{
		{"properties", "records", "items", "properties", "export", "properties", "parameters", "items", "properties"},
		{"properties", "records", "items", "properties", "pins", "items", "properties", "parameters", "items", "properties"},
	} {
		node := schema
		for _, key := range keys {
			next, ok := node[key].(map[string]any)
			if !ok {
				return nil, errors.New("graph scalar schema path missing")
			}
			node = next
		}
		if _, ok := node["value"]; !ok {
			return nil, errors.New("graph scalar schema value missing")
		}
		node["value"] = map[string]any{"oneOf": []any{
			map[string]any{"type": "string"}, map[string]any{"type": "boolean"},
			map[string]any{"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991},
		}}
	}
	return json.Marshal(schema)
}

type graphArgs struct {
	Dir            string   `json:"dir"`
	ProjectContext string   `json:"projectContext"`
	SourceInput    string   `json:"sourceInput"`
	Selectors      []string `json:"selectors"`
	ExpectedDigest string   `json:"expectedDigest"`
	Cursor         string   `json:"cursor"`
	Limit          int      `json:"limit"`
	MaxBytes       int      `json:"maxBytes"`
	Representation string   `json:"representation"`
	Cache          string   `json:"cache"`
}

func graphArgv(layer string, a graphArgs) []string {
	out := []string{"graph", layer}
	for _, x := range []struct{ k, v string }{{"project-context", a.ProjectContext}, {"dir", a.Dir}, {"source-input", a.SourceInput}, {"expected-digest", a.ExpectedDigest}, {"cursor", a.Cursor}, {"representation", a.Representation}, {"cache", a.Cache}} {
		if x.v != "" {
			out = append(out, "--"+x.k, x.v)
		}
	}
	for _, s := range a.Selectors {
		out = append(out, "--select", s)
	}
	if a.Limit != 0 {
		out = append(out, "--limit", strconv.Itoa(a.Limit))
	}
	if a.MaxBytes != 0 {
		out = append(out, "--max-bytes", strconv.Itoa(a.MaxBytes))
	}
	return out
}
func (s *Server) addGraphTools() {
	for _, v := range []struct {
		name, layer string
		op          resultdto.Operation
	}{{"graph_source", "source", resultdto.OperationGraphSource}, {"dependency_graph", "source", resultdto.OperationGraphSource}, {"graph_exports", "exports", resultdto.OperationGraphExports}, {"graph_ast", "ast", resultdto.OperationGraphAST}, {"graph_stats", "stats", resultdto.OperationGraphStats}} {
		spec := v
		tool := mcp.NewTool(spec.name, mcp.WithDescription("Captured "+spec.layer+" graph observation through installed CLI; separate from task-context delivery and execution permission. AST cache refresh explicitly writes only rebuildable cache."), mcp.WithString("dir", mcp.Required(), mcp.Description("Installed project root locator")), mcp.WithString("projectContext"), mcp.WithString("sourceInput", mcp.Description("Operator-enrolled source-selection file locator")), mcp.WithArray("selectors", mcp.WithStringItems()), mcp.WithString("expectedDigest"), mcp.WithString("cursor"), mcp.WithNumber("limit"), mcp.WithNumber("maxBytes"), mcp.WithString("representation", mcp.Enum("page", "whole")), mcp.WithString("cache", mcp.Enum("read", "off", "refresh")), outputSchema(spec.op))
		if spec.layer != "ast" {
			tool.Annotations.ReadOnlyHint = ptrGraphTrue()
		}
		s.mcp.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			raw, e := json.Marshal(req.Params.Arguments)
			if e != nil {
				return s.graphArgumentRefusal(spec.op, "arguments")
			}
			var a graphArgs
			if e = canonicaljson.DecodeStrict(raw, &a); e != nil {
				return s.graphArgumentRefusal(spec.op, "arguments")
			}
			cwd, failure := s.workDir(spec.op, "dir", a.Dir)
			if failure != nil {
				return failure, nil
			}
			call, ok := ctx.Value(graphCallKey{}).(*graphCall)
			if !ok || call == nil || !call.sdkBound || call.transport.server != s {
				return s.graphArgumentRefusal(spec.op, "graph transport")
			}
			layout := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: call.id, Ceiling: call.ceiling}
			encoded, err := resultwire.EncodeGraphFrame(layout)
			if err != nil {
				return s.graphArgumentRefusal(spec.op, "graph transport")
			}
			argv := append(graphArgv(spec.layer, a), "--graph-mcp-frame", encoded)
			out := s.callStructured(ctx, spec.op, cwd, argv, shortCall)
			call.expected, _ = resultwire.Frame(layout.RequestID(), out)
			return out, nil
		})
	}
}

// graphArgumentRefusal reports a failed tool result without a JSON-RPC error.
// Keep argument guards and SDK output validation on the structured failure path.
func (s *Server) graphArgumentRefusal(op resultdto.Operation, argument string) (*mcp.CallToolResult, error) {
	return s.argumentFailure(op, argument), nil
}

func ptrGraphTrue() *bool { v := true; return &v }

// graphCall is created only by the stdio adapter. The actual SDK initialization
// hook binds its ID; caller arguments and metadata cannot create this context.
type graphCallKey struct{}
type graphCall struct {
	transport *graphTransport
	raw       json.RawMessage
	id        json.RawMessage
	ctx       context.Context
	cancel    context.CancelFunc
	ceiling   int
	sdkBound  bool
	expected  []byte
}
type graphTransport struct {
	server    *Server
	input     *bufio.Reader
	output    io.Writer
	file      *os.File
	ctx       context.Context
	cancel    context.CancelFunc
	session   context.Context
	mu        sync.Mutex
	active    map[string]*graphCall
	workers   sync.WaitGroup
	writeGate chan struct{}
	pending   []byte
	closed    bool
	stopStdio context.CancelFunc
}

func graphTool(name string) bool {
	switch name {
	case "graph_source", "dependency_graph", "graph_exports", "graph_ast", "graph_stats":
		return true
	}
	return false
}
func (s *Server) installGraphHooks() {
	s.mcp.GetHooks().AddOnRequestInitialization(func(ctx context.Context, id any, message any) error {
		call, ok := ctx.Value(graphCallKey{}).(*graphCall)
		if !ok || call == nil || call.transport.server != s {
			return nil
		}
		raw, ok := message.(json.RawMessage)
		if !ok || len(raw) == 0 || len(raw) != len(call.raw) || &raw[0] != &call.raw[0] {
			return errors.New("GRAPH_ARGUMENT_INVALID")
		}
		encoded, err := json.Marshal(id)
		if err != nil || !bytes.Equal(encoded, call.id) {
			return errors.New("GRAPH_ARGUMENT_INVALID")
		}
		call.sdkBound = true
		return nil
	})
}
func newGraphTransport(ctx context.Context, s *Server, in io.Reader, out io.Writer, file *os.File) *graphTransport {
	owned, cancel := context.WithCancel(ctx)
	return &graphTransport{server: s, input: bufio.NewReader(in), output: out, file: file, ctx: owned, cancel: cancel, active: map[string]*graphCall{}, writeGate: make(chan struct{}, 1)}
}

// bindSession receives the SDK-created stdio session context before input runs.
func (g *graphTransport) bindSession(ctx context.Context) context.Context {
	g.session = ctx
	return ctx
}
func graphNullRefusal() []byte {
	return []byte("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"GRAPH_OUTPUT_BUDGET\"}}\n")
}
func (g *graphTransport) writeGraph(ctx context.Context, raw []byte) error {
	select {
	case g.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-g.writeGate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.file != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := g.file.SetWriteDeadline(deadline); err != nil {
				return err
			}
		}
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = g.file.SetWriteDeadline(time.Now()); close(done) })
		defer func() {
			if !stop() {
				<-done
			}
			_ = g.file.SetWriteDeadline(time.Time{})
		}()
	}
	n, err := g.output.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}

// Write forwards non-graph SDK frames unchanged under the same serialized output
// lock. A graph deadline is always cleared before any unrelated frame proceeds.
func (g *graphTransport) Write(raw []byte) (int, error) {
	g.writeGate <- struct{}{}
	defer func() { <-g.writeGate }()
	return g.output.Write(raw)
}

// Refusals have a transport-owned finite output lifetime, even when no request
// deadline exists. Failed output terminates input; no second frame is appended.
const graphRefusalWriteBudget = 250 * time.Millisecond

func (g *graphTransport) writeRefusal() error {
	ctx, cancel := context.WithTimeout(g.ctx, graphRefusalWriteBudget)
	defer cancel()
	if err := g.writeGraph(ctx, graphNullRefusal()); err != nil {
		g.cancel()
		if g.stopStdio != nil {
			g.stopStdio()
		}
		return err
	}
	return nil
}

func (g *graphTransport) Read(p []byte) (int, error) {
	for len(g.pending) == 0 {
		frame, err := readTransportFrame(g.ctx, g.input)
		if err == errTransportFrameLimit {
			refusalError := g.writeRefusal()
			g.cancel()
			if g.stopStdio != nil {
				g.stopStdio()
			}
			if refusalError != nil {
				return 0, refusalError
			}
			return 0, errTransportFrameHandled
		}
		line := frame.raw
		if len(line) == 0 {
			return 0, err
		}
		var route struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
			Params  struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		// Forward cancellation bytes unchanged, while also canceling the exact
		// graph-owned call. An unrelated duplicate-ID SDK error cannot displace it.
		var notification struct {
			Method string `json:"method"`
			Params struct {
				RequestID any `json:"requestId"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &notification) == nil && notification.Method == "notifications/cancelled" {
			encoded, _ := json.Marshal(notification.Params.RequestID)
			g.mu.Lock()
			call := g.active[string(encoded)]
			g.mu.Unlock()
			if call != nil {
				call.cancel()
			}
		}
		if json.Unmarshal(line, &route) != nil || route.Method != "tools/call" || !graphTool(route.Params.Name) {
			g.pending = line
			break
		}
		// Graph requests are consumed here; other requests preserve exact input bytes.
		// SDK parsing and validation still occur through the original registered server.
		id, idErr := json.Marshal(route.ID)
		ceiling := 16384
		var args graphArgs
		inputErr := canonicaljson.DecodeStrict(route.Params.Arguments, &args)
		if args.MaxBytes != 0 {
			ceiling = args.MaxBytes
		}
		layout := resultwire.GraphFrameLayout{APIVersion: resultwire.GraphFrameVersion, ID: id, Ceiling: ceiling}
		invalid := len(line) > 2<<20 || route.JSONRPC != "2.0" || idErr != nil || inputErr != nil || layout.Validate() != nil || g.session == nil
		if !invalid {
			_, err = canonicaljson.Canonicalize(line)
			invalid = err != nil
		}
		if !invalid {
			refusal, frameErr := resultwire.Frame(layout.RequestID(), mcp.NewToolResultError("GRAPH_OUTPUT_BUDGET"))
			invalid = frameErr != nil || len(refusal) > ceiling
		}
		if invalid {
			if err = g.writeRefusal(); err != nil {
				return 0, err
			}
			continue
		}
		g.mu.Lock()
		duplicate := g.active[string(id)] != nil
		if g.closed || len(g.active) >= 64 || duplicate {
			g.mu.Unlock()
			if err = g.writeRefusal(); err != nil {
				return 0, err
			}
			continue
		}
		owned, cancel := context.WithTimeout(g.session, g.server.timeout(shortCall))
		// Transport shutdown cancels every call, including a blocked child or output.
		stop := context.AfterFunc(g.ctx, cancel)
		call := &graphCall{transport: g, raw: append(json.RawMessage{}, line...), id: id, ctx: owned, cancel: cancel, ceiling: ceiling}
		g.active[string(id)] = call
		g.workers.Add(1)
		g.mu.Unlock()
		go func() { defer stop(); g.dispatch(call) }()
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}
func (g *graphTransport) dispatch(call *graphCall) {
	defer g.workers.Done()
	defer func() {
		call.cancel()
		g.mu.Lock()
		if g.active[string(call.id)] == call {
			delete(g.active, string(call.id))
		}
		g.mu.Unlock()
	}()
	ctx := context.WithValue(call.ctx, graphCallKey{}, call)
	response := g.server.mcp.HandleMessage(ctx, call.raw)
	raw, err := json.Marshal(response)
	if err != nil || response == nil {
		raw = graphNullRefusal()
	} else {
		raw = append(raw, '\n')
	}
	// The SDK's actual final serialized response, not a handler approximation,
	// determines delivery. A successful frame must equal the child-derived frame.
	if len(raw) > call.ceiling || len(call.expected) > 0 && !bytes.Equal(raw, call.expected) {
		raw = graphNullRefusal()
	}
	if err = g.writeGraph(call.ctx, raw); err != nil {
		// Broken/partial output is terminal. Never append a second success or refusal.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			g.cancel()
			if g.stopStdio != nil {
				g.stopStdio()
			}
		}
	}
}
func (g *graphTransport) close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed = true
	g.cancel()
	g.mu.Unlock()
	g.workers.Wait()
}
