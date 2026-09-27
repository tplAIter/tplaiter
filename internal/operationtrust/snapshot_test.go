package operationtrust

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestSnapshotFSRejectsUnboundResolution(t *testing.T) {
	if _, err := SnapshotFS(nil, nil); err == nil {
		t.Fatal("nil runtime/resolution accepted")
	}
	if _, err := SnapshotFS(&trustverify.Runtime{}, nil); err == nil {
		t.Fatal("nil resolution accepted")
	}
}
