package deps

import (
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

type closedSpy struct{ look, run int }

func (s *closedSpy) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	s.run++
	return execx.Result{Stdout: "SECRET", Stderr: "/host/path"}, errors.New("SECRET")
}
func (s *closedSpy) LookPath(string) (string, error) { s.look++; return "/host/path", nil }

func TestCheckIsExecutionClosed(t *testing.T) {
	r := &closedSpy{}
	got := Check(context.Background(), r, []manifest.Tool{{Name: "go"}, {Name: "docker"}, {Name: "../host"}})
	if len(got) != 3 || got[0].Found || got[0].Satisfies || !errors.Is(got[0].Err, ErrExecutionUnavailable) {
		t.Fatalf("Check=%#v", got)
	}
	if r.look != 0 || r.run != 0 {
		t.Fatalf("effects look=%d run=%d", r.look, r.run)
	}
}
