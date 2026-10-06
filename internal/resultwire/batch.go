package resultwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const BatchFrameVersion = "tplaiter.dev/run-batch-mcp-frame/v1"
const MaxBatchLayout = 8192

var ErrBatchBudget = errors.New("BATCH_OUTPUT_BUDGET")
var ErrBatchBinding = errors.New("BATCH_FRAME_BINDING_INVALID")

type BatchFrameLayout struct {
	APIVersion string          `json:"apiVersion"`
	ID         json.RawMessage `json:"normalizedID"`
	Ceiling    int             `json:"ceiling"`
}

func (l BatchFrameLayout) Validate() error {
	if l.APIVersion != BatchFrameVersion || l.Ceiling < 1024 || l.Ceiling > resultdto.MaxBatchFrame || len(l.ID) == 0 || len(l.ID) > resultdto.MaxBatchFrame {
		return ErrBatchBinding
	}
	var id any
	if json.Unmarshal(l.ID, &id) != nil {
		return ErrBatchBinding
	}
	switch id.(type) {
	case string, float64:
	default:
		return ErrBatchBinding
	}
	raw, e := json.Marshal(id)
	if e != nil || !bytes.Equal(raw, l.ID) {
		return ErrBatchBinding
	}
	rawLayout, err := canonicaljson.Canonical(l)
	if err != nil || len(rawLayout) > MaxBatchLayout {
		return ErrBatchBinding
	}
	return nil
}
func (l BatchFrameLayout) RequestID() mcp.RequestId {
	var id any
	_ = json.Unmarshal(l.ID, &id)
	return mcp.NewRequestId(id)
}

// BatchFramePlan is a defensive presentation reservation. It is not a permit.
type BatchFramePlan struct {
	envelope               []byte
	requests               []trustverify.ExecutionRequest
	layout                 *BatchFrameLayout
	cliMaximum, mcpMaximum int
}

func (p *BatchFramePlan) MaximumBytes() (cli, mcp int) {
	if p == nil {
		return 0, 0
	}
	return p.cliMaximum, p.mcpMaximum
}
func PlanBatchFrame(prepared resultdto.Result, layout *BatchFrameLayout) (*BatchFramePlan, error) {
	d, e := resultdto.DecodeBatchRunData(prepared.Data)
	if e != nil || d.Phase != "prepared" || prepared.Operation != resultdto.OperationProjectRunBatch || prepared.Status != resultdto.StatusOK || prepared.Project == nil {
		return nil, ErrBatchBinding
	}
	if e = batchEnvelope(prepared); e != nil {
		return nil, e
	}
	if d.PreparedRequests[0].ProjectID != prepared.Project.ID {
		return nil, ErrBatchBinding
	}
	raw, e := resultdto.MarshalCanonical(prepared)
	if e != nil {
		return nil, e
	}
	frozen, e := resultdto.Decode(raw)
	if e != nil {
		return nil, e
	}
	d, e = resultdto.DecodeBatchRunData(frozen.Data)
	if e != nil {
		return nil, e
	}
	p := &BatchFramePlan{requests: d.PreparedRequests}
	if layout != nil {
		if e = layout.Validate(); e != nil {
			return nil, e
		}
		owned := *layout
		owned.ID = append(json.RawMessage{}, layout.ID...)
		p.layout = &owned
	}
	p.envelope, e = batchEnvelopeIdentity(frozen)
	if e != nil {
		return nil, e
	}
	// Independent scalar maxima dominate every legal record shape. This private
	// sizing image intentionally combines maxima that need not be executable or
	// simultaneously valid. It is never decoded as a factual receipt or delivered.
	steps := make([]resultdto.BatchStepReceipt, len(p.requests))
	exit, writes := 255, 0
	for i, r := range p.requests {
		x := &resultdto.BatchProcessReceipt{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: r.RequestSHA256, OperationInputsSHA256: r.OperationInputsSHA256, InputClosureSHA256: r.Action.ContentClosureSHA256, ToolSHA256: r.Tool.BinarySHA256, Profile: "linux-static-fd-go127-poll/v1", ProfileSHA256: r.Tool.BinarySHA256, ImplementationSHA256: r.Tool.BinarySHA256, Launched: "unknown", Disposition: "recovery-required", ChildExitCode: &exit, Signal: 64, Stdout: bytes.Repeat([]byte{255}, resultdto.BatchStdoutLimit), Stderr: bytes.Repeat([]byte{255}, resultdto.BatchStderrLimit), StdoutSHA256: r.Tool.BinarySHA256, StderrSHA256: r.Tool.BinarySHA256, StdoutBytes: resultdto.BatchStdoutLimit, StderrBytes: resultdto.BatchStderrLimit, Cleanup: "pending", PersistentWrites: &writes}
		steps[i] = resultdto.BatchStepReceipt{Ordinal: i, Name: r.Action.ID, RequestSHA256: r.RequestSHA256, State: "attempted-unknown", Receipt: x}
	}
	bound := resultdto.BatchRunData{Phase: "executed", BatchReceipt: &resultdto.BatchReceipt{APIVersion: resultdto.BatchReceiptVersion, OperationInputsSHA256: p.requests[0].OperationInputsSHA256, Disposition: "recovery-required", Steps: steps}}
	if e = frozen.SetData(bound); e != nil {
		return nil, e
	}
	// Enumerate every permitted outer status/diagnostic shape using the real
	// result/v1 and SDK serializers, including summary and duplicated content.
	for _, status := range []resultdto.Status{resultdto.StatusOK, resultdto.StatusFailed, resultdto.StatusBlocked} {
		frozen.Status = status
		for _, code := range []string{"", "BATCH_RECOVERY_REQUIRED", "BATCH_STOPPED", "BATCH_CANCELLED", "BATCH_OUTPUT_BUDGET", "TRUST_ACTION_BATCH_EXECUTION_INCOMPLETE"} {
			frozen.Diagnostics = []resultdto.Diagnostic{}
			if code != "" {
				frozen.Diagnostics = []resultdto.Diagnostic{BatchDiagnostic(code)}
			}
			cli, mcp, e := batchFrames(frozen, p.layout)
			if e != nil {
				return nil, e
			}
			p.cliMaximum = max(p.cliMaximum, len(cli))
			p.mcpMaximum = max(p.mcpMaximum, len(mcp))
		}
	}
	// The complete prepared vector is also a mandatory delivery variant.
	cli, mcp, e := batchFrames(prepared, p.layout)
	if e != nil {
		return nil, e
	}
	p.cliMaximum = max(p.cliMaximum, len(cli))
	p.mcpMaximum = max(p.mcpMaximum, len(mcp))
	ceiling := resultdto.MaxBatchFrame
	if p.layout != nil {
		ceiling = p.layout.Ceiling
	}
	if p.cliMaximum > resultdto.MaxBatchFrame || p.mcpMaximum > ceiling {
		return nil, ErrBatchBudget
	}
	return p, nil
}
func EncodeBatchFrame(p *BatchFramePlan, actual resultdto.Result) (cli, mcp []byte, err error) {
	if p == nil || batchEnvelope(actual) != nil {
		return nil, nil, ErrBatchBinding
	}
	id, e := batchEnvelopeIdentity(actual)
	if e != nil || !bytes.Equal(id, p.envelope) {
		return nil, nil, ErrBatchBinding
	}
	d, e := resultdto.DecodeBatchRunData(actual.Data)
	if e != nil {
		return nil, nil, e
	}
	if d.Phase == "prepared" {
		if !reflect.DeepEqual(d.PreparedRequests, p.requests) {
			return nil, nil, ErrBatchBinding
		}
	} else {
		b := d.BatchReceipt
		if len(b.Steps) != len(p.requests) || b.OperationInputsSHA256 != p.requests[0].OperationInputsSHA256 {
			return nil, nil, ErrBatchBinding
		}
		for i, s := range b.Steps {
			r := p.requests[i]
			if s.RequestSHA256 != r.RequestSHA256 || s.Name != r.Action.ID {
				return nil, nil, ErrBatchBinding
			}
			if x := s.Receipt; x != nil && (x.InputClosureSHA256 != r.Action.ContentClosureSHA256 || x.ToolSHA256 != r.Tool.BinarySHA256) {
				return nil, nil, ErrBatchBinding
			}
		}
	}
	cli, mcp, e = batchFrames(actual, p.layout)
	if e != nil {
		return nil, nil, e
	}
	ceiling := resultdto.MaxBatchFrame
	if p.layout != nil {
		ceiling = p.layout.Ceiling
	}
	if len(cli) > p.cliMaximum || len(mcp) > p.mcpMaximum || len(cli) > resultdto.MaxBatchFrame || len(mcp) > ceiling {
		return nil, nil, ErrBatchBudget
	}
	return cli, mcp, nil
}
func batchFrames(env resultdto.Result, l *BatchFrameLayout) (cli, mcp []byte, err error) {
	raw, e := resultdto.MarshalCanonical(env)
	if e != nil {
		return nil, nil, e
	}
	cli = append(raw, '\n')
	if l != nil {
		mcp, e = Frame(l.RequestID(), Structured(env, env.Status != resultdto.StatusOK))
	}
	return cli, mcp, e
}
func batchEnvelopeIdentity(r resultdto.Result) ([]byte, error) {
	r.Data = nil
	r.Diagnostics = []resultdto.Diagnostic{}
	r.Status = resultdto.StatusOK
	return resultdto.MarshalCanonical(r)
}
func batchEnvelope(r resultdto.Result) error {
	if (r.Status != resultdto.StatusOK && r.Status != resultdto.StatusFailed && r.Status != resultdto.StatusBlocked) || r.Operation != resultdto.OperationProjectRunBatch || r.Project == nil || len(r.Changes) != 0 || len(r.Artifacts) != 0 || r.TransactionID != nil || r.Summary != (resultdto.Summary{}) || r.PlanSHA256 != "" || r.CurrentRef != "" || r.TargetRef != "" || len(r.Diagnostics) > 1 {
		return ErrBatchBinding
	}
	if len(r.Diagnostics) == 1 {
		d := r.Diagnostics[0]
		if !reflect.DeepEqual(d, BatchDiagnostic(d.Code)) || BatchDiagnostic(d.Code).Code == "" {
			return ErrBatchBinding
		}
	}
	return r.Validate()
}

// BatchDiagnostic is a finite factual failure vocabulary with no raw outputs.
func BatchDiagnostic(code string) resultdto.Diagnostic {
	messages := map[string]string{"TRUST_ACTION_BATCH_EXECUTION_INCOMPLETE": "the batch outcome requires recovery", "BATCH_RECOVERY_REQUIRED": "batch facts require recovery", "BATCH_STOPPED": "batch stopped after a terminal step", "BATCH_CANCELLED": "batch delivery was cancelled", "BATCH_OUTPUT_BUDGET": "the complete batch frame exceeds its reserved budget"}
	m, ok := messages[code]
	if !ok {
		return resultdto.Diagnostic{}
	}
	return resultdto.Diagnostic{Code: code, Severity: "error", Message: m, Details: map[string]any{}}
}

// EncodeBatchLayout is an internal presentation contract, not source admission.
func EncodeBatchLayout(l BatchFrameLayout) ([]byte, error) {
	if e := l.Validate(); e != nil {
		return nil, e
	}
	return canonicaljson.Canonical(l)
}
func BatchFrameDigest(raw []byte) string { return evidencecas.Digest(raw) }
