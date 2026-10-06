package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

// These are diagnostic frames only, with no source session or action authority.
func TestActionEarlyRefusalCannotBecomeDeliveryLease(t *testing.T) {
	e := resultdto.New(resultdto.OperationProjectRun, "test")
	e.Status = resultdto.StatusBlocked
	e.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_EVIDENCE_TAMPERED", Severity: "error", Message: "refused", Details: map[string]any{}}}
	if !actionEarlyRefusal(e) {
		t.Fatal("closed pre-admission diagnostic lost")
	}
	e.Status = resultdto.StatusOK
	if actionEarlyRefusal(e) {
		t.Fatal("success treated as refusal")
	}
	e.Status = resultdto.StatusBlocked
	if err := e.SetData(resultdto.ProjectRunData{Command: "check"}); err != nil {
		t.Fatal(err)
	}
	if actionEarlyRefusal(e) {
		t.Fatal("partial action data escaped delivery checks")
	}
}

// This is a pure factual adapter test. The manually constructed capture has
// no installed source, signer, permit or native launch authority.
func TestActionFactualFrameRefusesForgeryAndPreservesInnerExit(t *testing.T) {
	s := &Server{installed: true, stage: &heldStage{}}
	code := 3
	zero := 0
	digest := evidencecas.Digest([]byte("synthetic factual binding"))
	profile, _ := execx.ActionProfileDigest("linux-static-fd-go127/v1")
	receipt := execx.ActionProcessResult{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: digest, OperationInputsSHA256: digest, InputClosureSHA256: digest, ToolSHA256: digest, Profile: "linux-static-fd-go127/v1", ProfileSHA256: profile, ImplementationSHA256: digest, Launched: "yes", Disposition: "completed", ChildExitCode: &code, Stdout: []byte("found"), Stderr: []byte{}, StdoutSHA256: evidencecas.Digest([]byte("found")), StderrSHA256: evidencecas.Digest(nil), StdoutBytes: 5, OutputComplete: true, Cleanup: "reaped", PersistentWrites: &zero}
	env := resultdto.New(resultdto.OperationProjectRun, "test")
	env.Status = resultdto.StatusFailed
	env.Project = &resultdto.Project{ID: "synthetic-project", Root: "/synthetic"}
	if e := env.SetData(resultdto.ProjectRunData{Command: "check", ChildExitCode: 3, ActionReceipt: &receipt}); e != nil {
		t.Fatal(e)
	}
	raw, e := resultdto.MarshalCanonical(env)
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	capture := &actionCapture{owner: s, stage: s.stage, result: execx.Result{Stdout: string(raw), ExitCode: 10}, complete: true}
	retained, ok := s.knownActionFrame(capture, resultdto.OperationProjectRun)
	if !ok {
		t.Fatal("complete factual adapter frame rejected")
	}
	data := retained.Data
	if !bytes.Contains(data, []byte(`"childExitCode":3`)) {
		t.Fatal("inner exit overwritten")
	}
	for _, mutation := range []string{"owner", "untrusted", "partial", "duplicate", "unknown", "trailing", "tamper-output", "outer-op"} {
		t.Run(mutation, func(t *testing.T) {
			c := *capture
			server := *s
			operation := resultdto.OperationProjectRun
			switch mutation {
			case "owner":
				c.owner = &server
			case "untrusted":
				server.installed = false
				c.owner = &server
			case "partial":
				c.complete = false
			case "duplicate":
				c.result.Stdout = string(bytes.Replace(raw, []byte(`"childExitCode":3`), []byte(`"childExitCode":3,"childExitCode":3`), 1))
			case "unknown":
				c.result.Stdout = string(bytes.Replace(raw, []byte(`"data":{`), []byte(`"data":{"futureAuthority":true,`), 1))
			case "trailing":
				c.result.Stdout += string(raw)
			case "tamper-output":
				c.result.Stdout = string(bytes.Replace(raw, []byte(`"stdout":"Zm91bmQ="`), []byte(`"stdout":"bm8="`), 1))
			case "outer-op":
				operation = resultdto.OperationProjectNew
			}
			target := s
			if mutation == "untrusted" {
				target = &server
			}
			if _, ok := target.knownActionFrame(&c, operation); ok {
				t.Fatal("forged/incomplete capture accepted")
			}
		})
	}
	if _, ok := s.knownActionFrame(nil, resultdto.OperationProjectRun); ok {
		t.Fatal("missing actual capture accepted")
	}
}

// Real pipes and SDK-sized final frames exercise ownership/IO only. The test
// counterpart is not an admitted source session and cannot confer authority.
func TestActionFinalWriterCorrelationAndCancellation(t *testing.T) {
	for _, mode := range []string{"complete", "late-refusal", "blocked-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			input, control, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			replies, response, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			output, writer := io.Pipe()
			defer writer.Close()
			done := make(chan error, 1)
			child := &heldRootChild{ctx: ctx, cancel: cancel, control: control, replies: replies, output: output, reader: bufio.NewReaderSize(replies, 1025), token: "factual-test-only", digest: evidencecas.Digest([]byte("counter")), action: true, done: done}
			var rechecks atomic.Int32
			go func() {
				defer input.Close()
				defer response.Close()
				defer close(done)
				r := bufio.NewReader(input)
				for seq := 1; seq <= 2; seq++ {
					line, e := r.ReadBytes('\n')
					if e != nil {
						done <- e
						return
					}
					var msg rootDeliveryMessage
					if json.Unmarshal(line, &msg) != nil || msg.APIVersion != actionDeliveryVersion || msg.Token != child.token || msg.Digest != child.digest || msg.Sequence != seq {
						done <- io.ErrUnexpectedEOF
						return
					}
					reply := "closed"
					if seq == 1 {
						reply = "ready"
						rechecks.Add(1)
					}
					if mode == "late-refusal" {
						reply = "refused"
					}
					msg.Action = reply
					b, _ := json.Marshal(msg)
					if _, e = response.Write(append(b, '\n')); e != nil {
						done <- e
						return
					}
					if mode == "late-refusal" {
						return
					}
				}
			}()
			env := resultdto.New(resultdto.OperationProjectRun, "test")
			if e = env.SetData(resultdto.ProjectRunData{Command: "factual-counter"}); e != nil {
				t.Fatal(e)
			}
			result := structuredResult(env, false)
			if mode == "blocked-cancel" {
				result.Content = append(result.Content, mcp.TextContent{Type: "text", Text: string(bytes.Repeat([]byte("x"), 128<<10))})
			}
			frame, e := rootToolFrame(json.RawMessage(`1`), result)
			if e != nil {
				t.Fatal(e)
			}
			record := &rootFrame{id: json.RawMessage(`1`), ctx: ctx, cancel: cancel, child: child, action: true, expected: frame, ceiling: execx.MaxActionFrame, actionResult: &env}
			frames := &rootFrames{requests: map[string]*rootFrame{"1": record}, meta: map[*mcp.Meta]*rootFrame{}}
			server := &Server{version: "test"}
			var buffer bytes.Buffer
			w := &rootResponseWriter{frames: frames, server: server, out: &buffer}
			foreign := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"foreign\":true}}\n")
			if _, e = w.Write(foreign); e != nil || frames.requests["1"] != record || rechecks.Load() != 0 {
				t.Fatal("foreign reused ID consumed owner", e)
			}
			buffer.Reset()
			var pipeReader, pipeWriter *os.File
			if mode == "blocked-cancel" {
				pipeReader, pipeWriter, e = os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer pipeReader.Close()
				defer pipeWriter.Close()
				w.out = pipeWriter
			}
			start := time.Now()
			_, e = w.Write(frame)
			if mode == "blocked-cancel" {
				if e == nil || time.Since(start) > time.Second {
					t.Fatal("blocked final write did not cancel", e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				if mode == "complete" && !bytes.Equal(buffer.Bytes(), frame) {
					t.Fatal("complete serialized frame changed")
				}
				if mode == "late-refusal" && (!bytes.Contains(buffer.Bytes(), []byte("factual-counter")) || bytes.Contains(buffer.Bytes(), []byte("outerExitCode"))) {
					t.Fatal("late failure lost facts or invented outer exit")
				}
			}
			if rechecks.Load() != 1 || frames.requests["1"] != nil {
				t.Fatal("final owner not consumed/cleaned exactly once")
			}
		})
	}
}

func TestActionRunSchemaMatchesActualBase64Frame(t *testing.T) {
	raw, e := toolOutputSchema(resultdto.OperationProjectRun)
	if e != nil {
		t.Fatal(e)
	}
	schema := compileToolSchema(t, raw)
	code, zero := 0, 0
	digest := evidencecas.Digest([]byte("factual schema counter"))
	profile, _ := execx.ActionProfileDigest("linux-static-fd-go127-poll/v1")
	receipt := execx.ActionProcessResult{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: digest, OperationInputsSHA256: digest, InputClosureSHA256: digest, ToolSHA256: digest, Profile: "linux-static-fd-go127-poll/v1", ProfileSHA256: profile, ImplementationSHA256: digest, Launched: "yes", Disposition: "completed", ChildExitCode: &code, Stdout: []byte("actual byte wire"), Stderr: []byte{}, StdoutSHA256: evidencecas.Digest([]byte("actual byte wire")), StderrSHA256: evidencecas.Digest(nil), StdoutBytes: 16, OutputComplete: true, Cleanup: "reaped", PersistentWrites: &zero}
	env := resultdto.New(resultdto.OperationProjectRun, "test")
	env.Project = &resultdto.Project{ID: "factual", Root: "/neutral/project"}
	if e := env.SetData(resultdto.ProjectRunData{Command: "check", ActionReceipt: &receipt}); e != nil {
		t.Fatal(e)
	}
	validateStructured(t, schema, structuredResult(env, false), "base64 action receipt")
}
