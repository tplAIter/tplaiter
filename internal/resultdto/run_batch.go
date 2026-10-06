package resultdto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const OperationProjectRunBatch Operation = "project.run_batch"
const BatchReceiptVersion = "tplaiter.dev/action-batch-receipt/v1"
const MaxBatchFrame = 1 << 20
const MaxBatchSteps = 16
const BatchStdoutLimit = 128 << 10
const BatchStderrLimit = 16 << 10

var ErrBatchData = errors.New("BATCH_RECEIPT_INVALID")
var batchNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func init() { operationRegistry[OperationProjectRunBatch] = operationSpec{"RunBatch", ScopeProject} }

// BatchRunData contains observations, never an execution capability.
type BatchRunData struct {
	Phase            string                         `json:"phase"`
	PreparedRequests []trustverify.ExecutionRequest `json:"preparedRequests,omitempty"`
	BatchReceipt     *BatchReceipt                  `json:"batchReceipt,omitempty"`
}
type BatchReceipt struct {
	APIVersion            string             `json:"apiVersion"`
	OperationInputsSHA256 string             `json:"operationInputsSHA256"`
	Disposition           string             `json:"disposition"`
	Steps                 []BatchStepReceipt `json:"steps"`
}
type BatchStepReceipt struct {
	Ordinal       int                  `json:"ordinal"`
	Name          string               `json:"name"`
	RequestSHA256 string               `json:"requestSHA256"`
	State         string               `json:"state"`
	Receipt       *BatchProcessReceipt `json:"receipt"`
}

// BatchProcessReceipt is the closed factual action-receipt/v1 projection.
// It has no conversion to a runner, permit, material or authenticated session.
type BatchProcessReceipt struct {
	APIVersion            string `json:"apiVersion"`
	RequestSHA256         string `json:"requestSHA256"`
	OperationInputsSHA256 string `json:"operationInputsSHA256"`
	InputClosureSHA256    string `json:"inputClosureSHA256"`
	ToolSHA256            string `json:"toolSHA256"`
	Profile               string `json:"profile"`
	ProfileSHA256         string `json:"profileSHA256"`
	ImplementationSHA256  string `json:"implementationSHA256"`
	Launched              string `json:"launched"`
	Disposition           string `json:"disposition"`
	ChildExitCode         *int   `json:"childExitCode,omitempty"`
	Signal                int    `json:"signal"`
	Stdout                []byte `json:"stdout"`
	Stderr                []byte `json:"stderr"`
	StdoutSHA256          string `json:"stdoutSHA256"`
	StderrSHA256          string `json:"stderrSHA256"`
	StdoutBytes           int    `json:"stdoutBytes"`
	StderrBytes           int    `json:"stderrBytes"`
	OutputComplete        bool   `json:"outputComplete"`
	TimedOut              bool   `json:"timedOut"`
	Cancelled             bool   `json:"cancelled"`
	Overflow              bool   `json:"overflow"`
	Cleanup               string `json:"cleanup"`
	PersistentWrites      *int   `json:"persistentWrites,omitempty"`
}

func DecodeBatchRunData(raw []byte) (BatchRunData, error) {
	var d BatchRunData
	if len(raw) == 0 || len(raw) > MaxBatchFrame || decodeBatchWire(raw, &d) != nil || batchWire(raw, reflect.TypeFor[BatchRunData]()) != nil {
		return d, ErrBatchData
	}
	return d, ValidateBatchRunData(d)
}
func ValidateBatchRunData(d BatchRunData) error {
	switch d.Phase {
	case "prepared":
		if d.BatchReceipt != nil || len(d.PreparedRequests) < 1 || len(d.PreparedRequests) > MaxBatchSteps {
			return ErrBatchData
		}
		seen := map[string]bool{}
		var op, project string
		for _, r := range d.PreparedRequests {
			raw, e := json.Marshal(r)
			if e != nil {
				return ErrBatchData
			}
			if _, e = trustverify.DecodeExecutionRequest(raw); e != nil {
				return ErrBatchData
			}
			if !batchNamePattern.MatchString(r.Action.ID) || r.Scope != "run" || r.Action.Kind != "command" || r.Action.Shell || r.TimeoutMillis > 5000 || seen[r.RequestSHA256] {
				return ErrBatchData
			}
			if op != "" && (r.OperationInputsSHA256 != op || r.ProjectID != project) {
				return ErrBatchData
			}
			op = r.OperationInputsSHA256
			project = r.ProjectID
			seen[r.RequestSHA256] = true
		}
	case "executed":
		if d.PreparedRequests != nil || d.BatchReceipt == nil {
			return ErrBatchData
		}
		b := d.BatchReceipt
		if b.APIVersion != BatchReceiptVersion || !sha256Pattern.MatchString(b.OperationInputsSHA256) || !batchChoice(b.Disposition, "completed", "stopped", "recovery-required") || len(b.Steps) < 1 || len(b.Steps) > MaxBatchSteps {
			return ErrBatchData
		}
		seen := map[string]bool{}
		terminal := false
		allSuccess := true
		observedStop := false
		for i, s := range b.Steps {
			if s.Ordinal != i || !batchNamePattern.MatchString(s.Name) || !sha256Pattern.MatchString(s.RequestSHA256) || seen[s.RequestSHA256] {
				return ErrBatchData
			}
			seen[s.RequestSHA256] = true
			switch s.State {
			case "unstarted":
				if s.Receipt != nil {
					return ErrBatchData
				}
				terminal = true
				allSuccess = false
			case "attempted-unknown":
				if terminal || s.Receipt != nil {
					return ErrBatchData
				}
				terminal = true
				allSuccess = false
			case "observed":
				if terminal || s.Receipt == nil || validateBatchProcess(*s.Receipt) != nil || s.Receipt.RequestSHA256 != s.RequestSHA256 || s.Receipt.OperationInputsSHA256 != b.OperationInputsSHA256 {
					return ErrBatchData
				}
				x := s.Receipt
				success := x.ChildExitCode != nil && *x.ChildExitCode == 0 && x.Signal == 0 && x.OutputComplete && !x.Overflow && !x.Cancelled && !x.TimedOut && x.Launched == "yes" && x.Cleanup == "reaped" && x.Disposition == "completed"
				if !success {
					observedStop = true
					terminal = true
					allSuccess = false
				}
			default:
				return ErrBatchData
			}
		}
		if b.Disposition == "completed" && !allSuccess || b.Disposition == "stopped" && (allSuccess || !terminal || !observedStop) {
			return ErrBatchData
		}
	default:
		return ErrBatchData
	}
	return nil
}
func validateBatchProcess(x BatchProcessReceipt) error {
	for _, d := range []string{x.RequestSHA256, x.OperationInputsSHA256, x.InputClosureSHA256, x.ToolSHA256, x.ProfileSHA256, x.ImplementationSHA256} {
		if !sha256Pattern.MatchString(d) {
			return ErrBatchData
		}
	}
	if expected, ok := batchProfilePins[x.Profile]; !ok || x.ProfileSHA256 != expected {
		return ErrBatchData
	}
	if x.APIVersion != "tplaiter.dev/action-receipt/v1" || x.Stdout == nil || x.Stderr == nil || len(x.Stdout) > BatchStdoutLimit || len(x.Stderr) > BatchStderrLimit || len(x.Stdout) != x.StdoutBytes || len(x.Stderr) != x.StderrBytes || evidencecas.Digest(x.Stdout) != x.StdoutSHA256 || evidencecas.Digest(x.Stderr) != x.StderrSHA256 || x.Signal < 0 || x.Signal > 64 || x.Overflow && x.OutputComplete {
		return ErrBatchData
	}
	if !batchChoice(x.Launched, "yes", "no", "unknown") || !batchChoice(x.Disposition, "completed", "refused", "indeterminate", "recovery-required") || !batchChoice(x.Cleanup, "reaped", "pending", "failed") {
		return ErrBatchData
	}
	if x.ChildExitCode != nil && (*x.ChildExitCode < 0 || *x.ChildExitCode > 255 || x.Launched != "yes" || x.Signal != 0) || x.PersistentWrites != nil && (*x.PersistentWrites != 0 || x.Launched != "yes") || x.Signal != 0 && x.Launched != "yes" {
		return ErrBatchData
	}
	if x.Disposition == "completed" && (x.Launched != "yes" || x.ChildExitCode == nil && x.Signal == 0 || x.Cancelled || x.TimedOut || x.Overflow || !x.OutputComplete || x.Cleanup != "reaped") {
		return ErrBatchData
	}
	return nil
}
func batchChoice(s string, choices ...string) bool {
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}

// batchWire rejects missing/null required scalars, noncanonical base64 and
// native JSON case aliases before decoding can erase their distinction.
func batchWire(raw []byte, t reflect.Type) error {
	if bytes.Equal(raw, []byte("null")) {
		if t.Kind() == reflect.Pointer {
			return nil
		}
		return ErrBatchData
	}
	if t.Kind() == reflect.Pointer {
		return batchWire(raw, t.Elem())
	}
	if t == reflect.TypeFor[[]byte]() {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ErrBatchData
		}
		b, e := base64.StdEncoding.Strict().DecodeString(s)
		if e != nil || base64.StdEncoding.EncodeToString(b) != s {
			return ErrBatchData
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || m == nil {
			return ErrBatchData
		}
		allowed := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			k := tag[0]
			if k == "" || k == "-" {
				continue
			}
			allowed[k] = true
			v, ok := m[k]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !ok {
				if !optional {
					return ErrBatchData
				}
				continue
			}
			if optional && bytes.Equal(v, []byte("null")) {
				return ErrBatchData
			}
			if e := batchWire(v, f.Type); e != nil {
				return e
			}
		}
		for k := range m {
			if !allowed[k] {
				return ErrBatchData
			}
		}
	case reflect.Slice:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil || a == nil {
			return ErrBatchData
		}
		for _, v := range a {
			if e := batchWire(v, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}

// Exact semantic digests of the three published action-os-profile contracts.
// These are receipt validation pins, never platform capabilities.
var batchProfilePins = map[string]string{
	"darwin25G83-native-fd/v1":      "sha256:d63931fcb78b6d996ec86684aaea931ae9c50233c72d2a4c7c227cab89ef4142",
	"linux-static-fd-go127/v1":      "sha256:c461e9cd59a69b7274c9d6cc993024595eee70ff10c377a2c6661c06646468d0",
	"linux-static-fd-go127-poll/v1": "sha256:48fd4c9ce6bbc9a748b01c7ee3f3bb57077d6f48768ef76ed123a6944bbbf132",
}

// DecodeBatchProcessReceipt projects exact factual producer bytes. It creates
// no authority, and owns fresh output buffers rather than aliasing the producer.
func DecodeBatchProcessReceipt(raw []byte) (BatchProcessReceipt, error) {
	var x BatchProcessReceipt
	if len(raw) > MaxBatchFrame || decodeBatchWire(raw, &x) != nil || batchWire(raw, reflect.TypeFor[BatchProcessReceipt]()) != nil {
		return x, ErrBatchData
	}
	return x, validateBatchProcess(x)
}

// Unlike generic strict source inputs, factual JSON contains explicit nullable
// observations and JSON's base64 byte encoding. Preserve those closed unions.
func decodeBatchWire(raw []byte, dst any) error {
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
