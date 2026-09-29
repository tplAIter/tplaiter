package mcpsrv

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestLifecycleResultRoundTrip(t *testing.T) {
	r := resultdto.New(resultdto.OperationUpdateApply, "v1.2.3")
	r.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
	b, err := EncodeLifecycleResult(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeLifecycleResult([]byte(strings.TrimSuffix(string(b), "}") + `,"future":{"field":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLifecycleResult(got); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleExitCodeUsesTypedWrappedErrorsAndDoesNotParseText(t *testing.T) {
	typed := resultdto.NewError("TPL-E-TRUST-001", resultdto.ExitTrust, errors.New("trust denied"))
	if got := LifecycleExitCode(errors.Join(errors.New("context"), typed)); got != resultdto.ExitTrust {
		t.Fatalf("wrapped typed exit=%d", got)
	}
	if got := LifecycleExitCode(errors.New("trust denied")); got != resultdto.ExitInternal {
		t.Fatalf("text-derived exit=%d", got)
	}
}

func TestLifecycleResultRejectsUnknownMajor(t *testing.T) {
	r := resultdto.New(resultdto.OperationUpdatePlan, "dev")
	r.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
	b, err := EncodeLifecycleResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLifecycleResult([]byte(strings.Replace(string(b), resultdto.APIVersion, "tplaiter.dev/result/v2", 1))); err == nil {
		t.Fatal("accepted unknown major")
	}
}

func TestDecodeExpectedResultBindsOperationKindAndProcessExit(t *testing.T) {
	r := resultdto.New(resultdto.OperationSettingsShow, "dev")
	r.Project = &resultdto.Project{ID: "p", Root: "/work/p"}
	data, err := resultdto.MarshalCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExpectedResult(data, resultdto.OperationSettingsShow, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExpectedResult(data, resultdto.OperationSettingsSet, 0); err == nil {
		t.Fatal("accepted a valid result for the wrong requested operation")
	}
	r.Status = resultdto.StatusBlocked
	data, err = resultdto.MarshalCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExpectedResult(data, resultdto.OperationSettingsShow, int(resultdto.ExitTrust)); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExpectedResult(data, resultdto.OperationSettingsShow, 0); err == nil {
		t.Fatal("accepted blocked status with success exit")
	}
	if _, err := decodeExpectedResult(data, resultdto.OperationSettingsShow, 42); err == nil {
		t.Fatal("accepted an unregistered exit status")
	}
}

// TestSemanticParityNormalizesOnlyApprovedVolatileFields is the CLI↔MCP
// parity rule: two independent runs compare equal after volatile-only
// normalization, and any other difference is visible.
func TestSemanticParityNormalizesOnlyApprovedVolatileFields(t *testing.T) {
	left := resultdto.New(resultdto.OperationSettingsSet, "test")
	left.Project = &resultdto.Project{ID: "project", Root: "/tmp/cli/project"}
	left.Status = resultdto.StatusChanges
	left.Summary.FilesChanged = 1
	left.Changes = []resultdto.Change{{Path: "service.go", Action: "write"}}
	left.Diagnostics = []resultdto.Diagnostic{{Code: "TPL-W-SETTINGS-001", Severity: "warning", Message: "stable", Details: map[string]any{}}}
	leftTx := "tx-cli"
	left.TransactionID = &leftTx
	right := left.Canonical()
	right.Project.Root = "/tmp/mcp/project"
	rightTx := "tx-mcp"
	right.TransactionID = &rightTx
	if !semanticParityEqual(t, left, right) {
		t.Fatal("allowlisted transactionId and temporary root did not normalize")
	}
	right.Summary.FilesChanged++
	if semanticParityEqual(t, left, right) {
		t.Fatal("summary counter was incorrectly normalized")
	}
	right = left.Canonical()
	right.Diagnostics[0].Message = "changed"
	if semanticParityEqual(t, left, right) {
		t.Fatal("diagnostic was incorrectly normalized")
	}
}

func semanticParityEqual(t *testing.T, left, right resultdto.Result) bool {
	t.Helper()
	l, err := EncodeLifecycleResult(resultdto.NormalizeVolatile(left, "/tmp/cli", "/tmp/mcp"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := EncodeLifecycleResult(resultdto.NormalizeVolatile(right, "/tmp/cli", "/tmp/mcp"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(l, r)
}
