package resultdto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func batchReceiptFixture() BatchRunData {
	digest := evidencecas.Digest(nil)
	zero := 0
	x := &BatchProcessReceipt{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: digest, OperationInputsSHA256: digest, InputClosureSHA256: digest, ToolSHA256: digest, Profile: "linux-static-fd-go127-poll/v1", ProfileSHA256: batchProfilePins["linux-static-fd-go127-poll/v1"], ImplementationSHA256: digest, Launched: "yes", Disposition: "completed", ChildExitCode: &zero, Stdout: []byte{0, 255, 128, '\n'}, Stderr: []byte{}, StdoutBytes: 4, StdoutSHA256: evidencecas.Digest([]byte{0, 255, 128, '\n'}), StderrSHA256: digest, OutputComplete: true, Cleanup: "reaped", PersistentWrites: &zero}
	return BatchRunData{Phase: "executed", BatchReceipt: &BatchReceipt{APIVersion: BatchReceiptVersion, OperationInputsSHA256: digest, Disposition: "completed", Steps: []BatchStepReceipt{{Ordinal: 0, Name: "inspect", RequestSHA256: digest, State: "observed", Receipt: x}}}}
}
func TestBatchClosedFactualWire(t *testing.T) {
	d := batchReceiptFixture()
	raw, _ := json.Marshal(d)
	got, e := DecodeBatchRunData(raw)
	if e != nil {
		t.Fatal(e)
	}
	reencoded, _ := json.Marshal(got)
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("factual bytes changed")
	}
	// Unknown effects remain unknown, rather than inferred writes0.
	d.BatchReceipt.Steps[0].Receipt.PersistentWrites = nil
	raw, _ = json.Marshal(d)
	got, e = DecodeBatchRunData(raw)
	if e != nil || got.BatchReceipt.Steps[0].Receipt.PersistentWrites != nil {
		t.Fatal("unknown effect lost", e)
	}
	for name, mutate := range map[string]func(string) string{
		"required-bool":  func(s string) string { return strings.Replace(s, `"timedOut":false,`, "", 1) },
		"null-bool":      func(s string) string { return strings.Replace(s, `"timedOut":false`, `"timedOut":null`, 1) },
		"case-alias":     func(s string) string { return strings.Replace(s, `"phase"`, `"Phase"`, 1) },
		"extra-key":      func(s string) string { return strings.Replace(s, `"phase":`, `"extra":true,"phase":`, 1) },
		"duplicate-key":  func(s string) string { return strings.Replace(s, `"phase":`, `"phase":"executed","phase":`, 1) },
		"ordinal":        func(s string) string { return strings.Replace(s, `"ordinal":0`, `"ordinal":1`, 1) },
		"base64-newline": func(s string) string { return strings.Replace(s, `AP+ACg==`, `AP+ACg==\n`, 1) },
		"base64-padbits": func(s string) string { return strings.Replace(s, `AP+ACg==`, `AP+ACh==`, 1) },
		"hash":           func(s string) string { return strings.Replace(s, `"stdoutBytes":4`, `"stdoutBytes":3`, 1) },
		"profile":        func(s string) string { return strings.Replace(s, `linux-static-fd-go127-poll/v1`, `unconfined/v1`, 1) },
		"null-union": func(s string) string {
			return strings.Replace(s, `"phase":"executed",`, `"phase":"executed","preparedRequests":null,`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeBatchRunData([]byte(mutate(string(raw)))); e == nil {
				t.Fatal("invalid factual image admitted")
			}
		})
	}
}
func TestBatchCompleteTerminalOrdinalFacts(t *testing.T) {
	d := batchReceiptFixture()
	b := d.BatchReceipt
	x := b.Steps[0].Receipt
	nonzero := 7
	x.ChildExitCode = &nonzero
	b.Disposition = "stopped"
	second := BatchStepReceipt{Ordinal: 1, Name: "later", RequestSHA256: evidencecas.Digest([]byte("later")), State: "unstarted"}
	b.Steps = append(b.Steps, second)
	if e := ValidateBatchRunData(d); e != nil {
		t.Fatal(e)
	}
	b.Steps[1].State = "observed"
	b.Steps[1].Receipt = x
	if e := ValidateBatchRunData(d); e == nil {
		t.Fatal("facts fabricated after stop")
	}
	b.Steps[1] = second
	b.Disposition = "completed"
	if e := ValidateBatchRunData(d); e == nil {
		t.Fatal("incomplete batch claimed completed")
	}
	b.Disposition = "recovery-required"
	b.Steps[0].State = "attempted-unknown"
	b.Steps[0].Receipt = nil
	if e := ValidateBatchRunData(d); e != nil {
		t.Fatal("genuine unknown attempt refused", e)
	}
}

func TestBatchNativeNameDomain(t *testing.T) {
	d := batchReceiptFixture()
	d.BatchReceipt.Steps[0].Name = "7inspect"
	if e := ValidateBatchRunData(d); e != nil {
		t.Fatal("valid producer name rejected", e)
	}
	for _, name := range []string{"Inspect", "-inspect", "inspect:name"} {
		d.BatchReceipt.Steps[0].Name = name
		if ValidateBatchRunData(d) == nil {
			t.Fatal("non-native name admitted", name)
		}
	}
}
