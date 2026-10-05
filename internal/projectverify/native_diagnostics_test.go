package projectverify

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
)

func TestNativeJournalPublicDiagnostics(t *testing.T) {
	for _, test := range []struct {
		status inventory.Status
		code   string
		exit   resultdto.ExitCode
	}{
		{inventory.StatusActive, TransactionCode, resultdto.ExitTransaction},
		{inventory.StatusFuture, TransactionCode, resultdto.ExitTransaction},
		{inventory.StatusUnsupportedKind, TransactionCode, resultdto.ExitTransaction},
		{inventory.StatusUnresolved, TransactionCode, resultdto.ExitTransaction},
		{inventory.StatusMissingImages, TransactionCode, resultdto.ExitTransaction},
		{inventory.StatusMissingCAS, OfflineMissCode, resultdto.ExitUnavailable},
		{inventory.StatusUnsafe, StateCode, resultdto.ExitOperational},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			mapped := classify(&runtimeassembly.JournalError{ID: "internal-only", Status: test.status})
			diagnostics := resultdto.ProjectDiagnostics(mapped)
			if resultdto.Classify(mapped) != test.exit || len(diagnostics) != 1 || diagnostics[0].Code != test.code {
				t.Fatalf("wrong projection: %+v", diagnostics)
			}
			if len(diagnostics[0].Details) != 0 {
				t.Fatal("internal journal identity leaked in public details")
			}
		})
	}
}
