package actioncmd

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// These refusal controls mint no runtime, signed grant or native admission.
func TestActionSessionRefusesMissingLiveCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx, context.Background()} {
		if s, e := Prepare(c, nil, nil, operationtrust.ActionInput{Name: "check", ParametersJSON: []byte("{}")}); e == nil || s != nil {
			t.Fatal("missing installed carrier accepted")
		}
	}
	for _, s := range []*Session{nil, {}} {
		if _, e := s.Request(); e == nil {
			t.Fatal("zero session request")
		}
		if e := s.Recheck(context.Background()); e == nil {
			t.Fatal("zero session recheck")
		}
		if _, e := s.Execute(context.Background(), trustverify.ApprovalRefs{}); e == nil {
			t.Fatal("zero session execution")
		}
		if e := s.EnterBootstrap(context.Background(), execx.ActionBootstrapControl{}); e == nil {
			t.Fatal("zero session bootstrap")
		}
		s.Close()
		s.Close()
	}
}
