// Package resultdto defines the stable result/v1 envelope that every
// tplaiter command emits with --json and that every MCP tool returns as
// structured content.
//
// The package is deliberately independent from command and transaction
// implementations. Producers build a [Result], and [MarshalCanonical] both
// validates it and produces the canonical bytes; consumers use [Decode]. The
// CLI and MCP projections are therefore interchangeable byte for byte.
package resultdto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// APIVersion identifies the envelope contract. A new major version is a
	// new constant; decoders reject unknown majors.
	APIVersion = "tplaiter.dev/result/v1"
	// SchemaVersion is the minor schema revision inside APIVersion.
	SchemaVersion = 1
)

// Status is the envelope outcome. It is always consistent with the process
// exit code (see [ValidateStatusExit]).
type Status string

const (
	StatusOK            Status = "ok"
	StatusChanges       Status = "changes"
	StatusConflicted    Status = "conflicted"
	StatusBlocked       Status = "blocked"
	StatusFailed        Status = "failed"
	StatusNotApplicable Status = "not-applicable"
)

// Project identifies the project an operation acted on.
type Project struct {
	ID   string `json:"id"`
	Root string `json:"root"`
}

// Summary carries the counters every operation reports.
type Summary struct {
	FilesChanged  int `json:"filesChanged"`
	BlocksChanged int `json:"blocksChanged"`
	Conflicts     int `json:"conflicts"`
}

// Change is one file (or managed block) an operation created, changed or
// would change.
type Change struct {
	Path     string `json:"path"`
	BlockID  string `json:"blockId,omitempty"`
	Provider string `json:"provider,omitempty"`
	Action   string `json:"action"`
}

// Diagnostic is one typed finding or failure. Code is the stable identity;
// Message is a deterministic, safe text that never embeds raw child output.
type Diagnostic struct {
	Code     string         `json:"code"`
	Severity string         `json:"severity"`
	Message  string         `json:"message"`
	Path     string         `json:"path,omitempty"`
	BlockID  string         `json:"blockId,omitempty"`
	Hint     string         `json:"hint,omitempty"`
	Details  map[string]any `json:"details"`
}

// Artifact is a file produced next to the project (plans, reports).
type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Meta describes the producer.
type Meta struct {
	TplaiterVersion string `json:"tplaiterVersion"`
	SchemaVersion   int    `json:"schemaVersion"`
}

// Result is the result/v1 wire envelope. Slices and Diagnostic.Details are
// normalized to empty values, never null. Project is null for operations that
// do not act on a project (see [ScopeForOperation]). Data carries the
// operation-specific payload described by the operation's data schema.
type Result struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	Operation     Operation       `json:"operation"`
	Status        Status          `json:"status"`
	Project       *Project        `json:"project"`
	TransactionID *string         `json:"transactionId"`
	Summary       Summary         `json:"summary"`
	Changes       []Change        `json:"changes"`
	Diagnostics   []Diagnostic    `json:"diagnostics"`
	Artifacts     []Artifact      `json:"artifacts"`
	Meta          Meta            `json:"meta"`
	PlanSHA256    string          `json:"planSha256,omitempty"`
	CurrentRef    string          `json:"currentRef,omitempty"`
	TargetRef     string          `json:"targetRef,omitempty"`
	Data          json.RawMessage `json:"data,omitempty"`
}

// Envelope is the descriptive name used by protocol documentation.
type Envelope = Result

// New returns an envelope for operation with every collection initialized.
// The kind comes from the operation registry; an unknown operation yields an
// envelope that fails validation.
func New(operation Operation, version string) Result {
	kind, _ := KindForOperation(operation)
	return Result{
		APIVersion: APIVersion, Kind: kind, Operation: operation, Status: StatusOK,
		Changes: []Change{}, Diagnostics: []Diagnostic{}, Artifacts: []Artifact{},
		Meta: Meta{TplaiterVersion: version, SchemaVersion: SchemaVersion},
	}
}

// SetData stores the operation-specific payload. A nil value clears it.
func (r *Result) SetData(v any) error {
	if v == nil {
		r.Data = nil
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("resultdto: encode data: %w", err)
	}
	r.Data = raw
	return nil
}

// UnmarshalJSON enforces the wire shape (required fields, non-null arrays, no
// duplicate keys) and then validates the decoded value.
func (r *Result) UnmarshalJSON(data []byte) error {
	if err := validateWireShape(data); err != nil {
		return err
	}
	type wire Result
	var v wire
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*r = Result(v)
	return r.Validate()
}

func normalize(r *Result) {
	if r.Changes == nil {
		r.Changes = []Change{}
	}
	if r.Diagnostics == nil {
		r.Diagnostics = []Diagnostic{}
	}
	if r.Artifacts == nil {
		r.Artifacts = []Artifact{}
	}
	for i := range r.Diagnostics {
		if r.Diagnostics[i].Details == nil {
			r.Diagnostics[i].Details = map[string]any{}
		}
	}
}

// MarshalCanonical validates r and emits its canonical JSON representation:
// sorted collections, normalized empty values and canonical data bytes. The
// same logical result always produces the same bytes.
func MarshalCanonical(r Result) ([]byte, error) {
	normalize(&r)
	r, err := r.canonical()
	if err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// Decode parses and validates a result/v1 document. Unknown additive fields
// are accepted; unknown major versions, schema versions, operations and
// statuses are rejected.
func Decode(data []byte) (Result, error) {
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, err
	}
	return r, nil
}

var requiredTopLevelFields = []string{
	"apiVersion", "kind", "operation", "status", "project", "transactionId",
	"summary", "changes", "diagnostics", "artifacts", "meta",
}

// nullableTopLevelFields may be JSON null but must be present.
var nullableTopLevelFields = map[string]bool{"project": true, "transactionId": true}

// validateWireShape protects the decoder boundary without rejecting unknown
// additive fields. json.Unmarshal otherwise cannot distinguish omitted fields
// from zero values, nor null arrays from empty arrays.
func validateWireShape(data []byte) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return err
	}
	if top == nil {
		return errors.New("result must be a JSON object")
	}
	for _, field := range requiredTopLevelFields {
		raw, ok := top[field]
		if !ok || (!nullableTopLevelFields[field] && isJSONNull(raw)) {
			return fmt.Errorf("result: required field %q is missing or null", field)
		}
	}
	if !isJSONNull(top["project"]) {
		if err := requireObject(top["project"], "project", "id", "root"); err != nil {
			return err
		}
	}
	if err := requireObject(top["summary"], "summary", "filesChanged", "blocksChanged", "conflicts"); err != nil {
		return err
	}
	if err := requireObject(top["meta"], "meta", "tplaiterVersion", "schemaVersion"); err != nil {
		return err
	}
	if raw, ok := top["data"]; ok && isJSONNull(raw) {
		return errors.New("result: data must be omitted rather than null")
	}
	if err := requireArray(top["changes"], "changes", func(v json.RawMessage, i int) error {
		name := fmt.Sprintf("changes[%d]", i)
		if err := requireObject(v, name, "path", "action"); err != nil {
			return err
		}
		return rejectNullObjectFields(v, name, "blockId", "provider")
	}); err != nil {
		return err
	}
	if err := requireArray(top["diagnostics"], "diagnostics", func(v json.RawMessage, i int) error {
		name := fmt.Sprintf("diagnostics[%d]", i)
		if err := requireObject(v, name, "code", "severity", "message", "details"); err != nil {
			return err
		}
		return rejectNullObjectFields(v, name, "path", "blockId", "hint")
	}); err != nil {
		return err
	}
	return requireArray(top["artifacts"], "artifacts", func(v json.RawMessage, i int) error {
		return requireObject(v, fmt.Sprintf("artifacts[%d]", i), "name", "path", "sha256")
	})
}

func requireObject(raw json.RawMessage, name string, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be an object", name)
	}
	for _, field := range fields {
		if value, ok := object[field]; !ok || isJSONNull(value) {
			return fmt.Errorf("%s: required field %q is missing or null", name, field)
		}
	}
	return nil
}

func rejectNullObjectFields(raw json.RawMessage, name string, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be an object", name)
	}
	for _, field := range fields {
		if value, ok := object[field]; ok && isJSONNull(value) {
			return fmt.Errorf("%s field %q must not be null", name, field)
		}
	}
	return nil
}

func requireArray(raw json.RawMessage, name string, check func(json.RawMessage, int) error) error {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return fmt.Errorf("%s must be a non-null array", name)
	}
	for i, value := range values {
		if err := check(value, i); err != nil {
			return err
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("result contains trailing JSON data")
		}
		return err
	}
	return nil
}

// maxJSONDepth bounds recursion on hostile input.
const maxJSONDepth = 128

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("result JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token() // closing }
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token() // closing ]
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

// ValidateExit checks that r is valid and that its status agrees with the
// process exit code the producer reported.
func (r Result) ValidateExit(code ExitCode) error {
	if !code.Valid() {
		return fmt.Errorf("invalid exit code %d", code)
	}
	if err := r.Validate(); err != nil {
		return err
	}
	// Status queries are observational: exit 0 means the observation
	// succeeded, while result.status describes the observed transaction.
	if (r.Operation == OperationUpdateStatus || r.Operation == OperationNewStatus) && code == ExitSuccess {
		return nil
	}
	// Historical settings text conflicts are committed outcomes with process
	// status 2. This exception does not change generic usage/conflict exit rules.
	if code == ExitCode(2) && r.Status == StatusConflicted && (r.Operation == OperationSettingsSet || r.Operation == OperationSettingsReanswer) && r.TransactionID != nil && *r.TransactionID != "" && r.Summary.Conflicts > 0 && len(r.Changes) > 0 {
		return nil
	}
	return ValidateStatusExit(r.Status, code)
}
