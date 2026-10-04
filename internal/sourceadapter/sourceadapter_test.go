package sourceadapter

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestResolveRefusesMissingOrClosedRuntimeBeforeRegistry(t *testing.T) {
	for _, runtime := range []*trustload.Runtime{nil, {}} {
		if _, err := Resolve(context.Background(), runtime, "/nonexistent/home", "fixture/template", []byte(`{}`)); err == nil {
			t.Fatal("unbound runtime accepted")
		}
	}
}

func TestLocalCommitRefusesOptionAndControlInjection(t *testing.T) {
	for _, ref := range []string{"", "--help", "main\nrefs/heads/other", "main\x00other"} {
		if _, err := localCommit(context.Background(), "/nonexistent", ref); err == nil {
			t.Fatal("invalid ref accepted")
		}
	}
}
