package resultwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func batchPreparedFixture(t *testing.T, n int) resultdto.Result {
	t.Helper()
	digest := evidencecas.Digest(nil)
	requests := make([]trustverify.ExecutionRequest, n)
	for i := range requests {
		r := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: digest, OperationInputsSHA256: digest, ProjectID: "project.test", Scope: "run", Provider: trustverify.Provider{Origin: "origin.test", TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: digest, ContractSHA256: digest}, Action: trustverify.Action{ID: fmt.Sprintf("inspect%d", i), Kind: "command", Phase: "standalone", Argv: []string{"tool.test"}, ContentClosureSHA256: digest}, Tool: trustverify.Tool{ID: "tool.test", Version: "1", BinarySHA256: digest, OptionsSHA256: digest}, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: digest, TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}
		r.RequestSHA256, _ = r.ComputeRequestSHA256()
		requests[i] = r
	}
	env := resultdto.New(resultdto.OperationProjectRunBatch, "test")
	env.Project = &resultdto.Project{ID: "project.test", Root: "/tmp/project<>&\""}
	if e := env.SetData(resultdto.BatchRunData{Phase: "prepared", PreparedRequests: requests}); e != nil {
		t.Fatal(e)
	}
	return env
}
func batchActualFixture(t *testing.T, env resultdto.Result, maxOutput bool) resultdto.Result {
	t.Helper()
	d, e := resultdto.DecodeBatchRunData(env.Data)
	if e != nil {
		t.Fatal(e)
	}
	b := &resultdto.BatchReceipt{APIVersion: resultdto.BatchReceiptVersion, OperationInputsSHA256: d.PreparedRequests[0].OperationInputsSHA256, Disposition: "completed", Steps: make([]resultdto.BatchStepReceipt, len(d.PreparedRequests))}
	zero := 0
	for i, r := range d.PreparedRequests {
		stdout, stderr := []byte{0, 255, '\n'}, []byte{128}
		if maxOutput {
			stdout = bytes.Repeat([]byte{255}, resultdto.BatchStdoutLimit)
			stderr = bytes.Repeat([]byte{255}, resultdto.BatchStderrLimit)
		}
		x := &resultdto.BatchProcessReceipt{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: r.RequestSHA256, OperationInputsSHA256: r.OperationInputsSHA256, InputClosureSHA256: r.Action.ContentClosureSHA256, ToolSHA256: r.Tool.BinarySHA256, Profile: "linux-static-fd-go127-poll/v1", ProfileSHA256: "sha256:48fd4c9ce6bbc9a748b01c7ee3f3bb57077d6f48768ef76ed123a6944bbbf132", ImplementationSHA256: r.Tool.BinarySHA256, Launched: "yes", Disposition: "completed", ChildExitCode: &zero, Stdout: stdout, Stderr: stderr, StdoutSHA256: evidencecas.Digest(stdout), StderrSHA256: evidencecas.Digest(stderr), StdoutBytes: len(stdout), StderrBytes: len(stderr), OutputComplete: true, Cleanup: "reaped", PersistentWrites: &zero}
		b.Steps[i] = resultdto.BatchStepReceipt{Ordinal: i, Name: r.Action.ID, RequestSHA256: r.RequestSHA256, State: "observed", Receipt: x}
	}
	if e := env.SetData(resultdto.BatchRunData{Phase: "executed", BatchReceipt: b}); e != nil {
		t.Fatal(e)
	}
	return env
}
func TestBatchWholeFrameReservationAndFactualEncoding(t *testing.T) {
	env := batchPreparedFixture(t, 2)
	id, _ := json.Marshal(strings.Repeat("<>&\"\n", 32))
	layout := &BatchFrameLayout{APIVersion: BatchFrameVersion, ID: id, Ceiling: resultdto.MaxBatchFrame}
	plan, e := PlanBatchFrame(env, layout)
	if e != nil {
		t.Fatal(e)
	}
	cliMax, mcpMax := plan.MaximumBytes()
	t.Logf("two-step maximum CLI=%d MCP=%d", cliMax, mcpMax)
	actual := batchActualFixture(t, env, true)
	cli, frame, e := EncodeBatchFrame(plan, actual)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := Frame(layout.RequestID(), Structured(actual, false))
	if !bytes.Equal(frame, expected) || cli[len(cli)-1] != '\n' || frame[len(frame)-1] != '\n' {
		t.Fatal("actual SDK bytes changed")
	}
	exact := *layout
	exact.Ceiling = mcpMax
	if _, e = PlanBatchFrame(env, &exact); e != nil {
		t.Fatal("maximum boundary refused", e)
	}
	exact.Ceiling--
	if _, e = PlanBatchFrame(env, &exact); !errors.Is(e, ErrBatchBudget) {
		t.Fatal("one below reserved floor accepted", e)
	}
	if _, e = PlanBatchFrame(batchPreparedFixture(t, 6), layout); !errors.Is(e, ErrBatchBudget) {
		t.Fatal("six whole output maxima admitted", e)
	}
	// Caller mutation cannot replace private planned metadata/request identity.
	layout.ID[1] = 'x'
	env.Project.Root = "/changed"
	if _, _, e = EncodeBatchFrame(plan, env); !errors.Is(e, ErrBatchBinding) {
		t.Fatal("changed project binding admitted", e)
	}
	actual.Diagnostics = []resultdto.Diagnostic{{Code: "LEAK", Severity: "error", Message: strings.Repeat("unsafe", 1000), Details: map[string]any{}}}
	if _, _, e = EncodeBatchFrame(plan, actual); !errors.Is(e, ErrBatchBinding) {
		t.Fatal("unreserved diagnostics admitted", e)
	}
}
