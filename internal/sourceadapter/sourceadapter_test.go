package sourceadapter

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
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

func TestRootLocatorExactCommitDoesNotGrantSource(t *testing.T) {
	subject := operationtrust.SelectionSubject{Commit: "0123456789012345678901234567890123456789"}
	alias, name, version, err := resolveRootLocator(context.Background(), "/nonexistent/home", subject.Commit, subject)
	if err != nil || alias != "pinned" || name != "" || version != subject.Commit {
		t.Fatalf("exact locator: %s %s %s %v", alias, name, version, err)
	}
	if _, err := ResolveContextSources(context.Background(), &trustload.Runtime{}, "/nonexistent/home", subject.Commit, []byte(`{}`)); err == nil {
		t.Fatal("locator minted authority")
	}
}
