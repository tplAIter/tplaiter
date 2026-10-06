package contextsource

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestRecordedNativeUpdateOwnsBothClosuresAndNoActions(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	source, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	in := NativeUpdateInput{SourceRender: renderref.Input{Values: settings.Values{}}, TargetRender: renderref.Input{Values: settings.Values{}}, SourceRecordedValues: settings.Values{}, TargetRecordedValues: settings.Values{}, RendererVersion: "1.0.0", PreimageSHA256: evidencecas.Digest([]byte("actual owner observation"))}
	p, err := PrepareNativeUpdate(ctx, f.runtime, source, target, in)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	op, err := p.OperationBase(ctx, f.runtime)
	if err != nil || op.Scope != "update" || len(op.Subjects) != 4 || len(op.Actions) != 0 || op.PreimageSHA256 != in.PreimageSHA256 {
		t.Fatalf("incorrect calculation: %+v %v", op, err)
	}
	op.Subjects[0].Commit = "tampered"
	again, err := p.OperationBase(ctx, f.runtime)
	if err != nil || again.Subjects[0].Commit == "tampered" {
		t.Fatal("mutable subjects", err)
	}
	a, err := p.SourceDependencyLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.TargetDependencyLock(ctx, f.runtime)
	if err != nil || a.LockSHA256 != b.LockSHA256 || len(a.Dependencies) != 3 {
		t.Fatal("lost closure", err)
	}
	if p.RecheckFor(ctx, &trustload.Runtime{}) == nil {
		t.Fatal("foreign runtime")
	}
	target.Close()
	if p.RecheckFor(ctx, f.runtime) == nil {
		t.Fatal("closed target accepted")
	}
}

func TestRecordedNativeUpdateCannotBeFabricated(t *testing.T) {
	p := &PreparedNativeUpdate{}
	if _, err := p.OperationBase(context.Background(), &trustload.Runtime{}); err == nil {
		t.Fatal("fabricated Update")
	}
}

func TestRecordedNativeUpdateRejectsSameAdmittedCarrierForBothRoles(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	sources, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	in := NativeUpdateInput{SourceRender: renderref.Input{Values: settings.Values{}}, TargetRender: renderref.Input{Values: settings.Values{}}, RendererVersion: "1.0.0", PreimageSHA256: evidencecas.Digest([]byte("same-carrier"))}
	if _, err := PrepareNativeUpdate(ctx, f.runtime, sources, sources, in); err == nil {
		t.Fatal("same admitted source carrier accepted for both update roles")
	}
}
