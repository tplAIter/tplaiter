package blockformatter

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestManagedFormatterSignedPasses(t *testing.T) {
	f := testfixture.NewGofmtFixture(t)
	r, res := f.Open(t)
	defer r.Close()
	ctx := context.Background()
	a, err := NewRuntimeAdapter(r)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("package fixture\nfunc f(){ }\n")
	options, _ := trustverify.ComputeToolOptionsSHA256([]string{})
	tool := trustverify.Tool{ID: "gofmt", Version: strings.TrimPrefix(runtimeGoVersion(t, f.Tool()), "go"), BinarySHA256: evidencecas.Digest(f.Tool()), OptionsSHA256: options}
	plan, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	d := evidencecas.Digest([]byte("fixture"))
	contextJSON, err := canonicaljson.Canonical(operationtrust.ManagedFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v1", Role: "clean-target", SourceRootLockSHA256: d, TargetRootLockSHA256: d, ReplacementDeclarationsSHA256: d, DecisionsSHA256: d, ObservedProjectSHA256: d, ObservedRegistrySHA256: d, RendererAnswersSHA256: d})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := a.SelectManaged(ctx, res, res, plan, input, contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := a.Select(ctx, res, res, plan, input)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Actions()[0].Action.ID == ordinary.Actions()[0].Action.ID || selected.Actions()[0].Action.ContentClosureSHA256 == ordinary.Actions()[0].Action.ContentClosureSHA256 {
		t.Fatal("context omitted from identity")
	}
	binding, _ := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: binding, ProjectID: r.ProjectContext().ProjectID, Scope: "run", PreimageSHA256: d, AnswersSHA256: d, Subjects: []trustverify.Provider{providerFromResolution(res)}, Actions: selected.Actions()}
	p, err := a.Bind(ctx, selected, op)
	if err != nil {
		t.Fatal(err)
	}
	reqs := p.Requests()
	for i, req := range reqs {
		m, err := p.materials[i].StagedFor(ctx, r.TrustRuntime(), req)
		if err != nil || len(m.Content) != 4 {
			t.Fatalf("staging: %v", err)
		}
	}
	refs := []trustverify.ApprovalRefs{f.Approval(t, reqs[0]), f.Approval(t, reqs[1])}
	passes, err := a.AuthorizePasses(ctx, p, refs)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.RunPass(ctx, passes, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.RunPass(ctx, passes, 2)
	if err != nil {
		t.Fatal(err)
	}
	x, err := first.DataFor(r)
	if err != nil {
		t.Fatal(err)
	}
	y, err := second.DataFor(r)
	if err != nil {
		t.Fatal(err)
	}
	result, err := CheckRetainedPair(x, y)
	if err != nil || bytes.Equal(result.Formatted, input) {
		t.Fatalf("actual pair: %v", err)
	}
	if !bytes.Equal(x.Input, y.Input) || x.Request.RequestSHA256 == y.Request.RequestSHA256 {
		t.Fatal("original input/distinct requests")
	}
	again, err := first.DataFor(r)
	if err != nil || !again.CompletedAt.Equal(x.CompletedAt) {
		t.Fatal("completion observation changed")
	}
	if err := r.TrustRuntime().VerifyRetainedApproval(ctx, res, x.Operation, x.Request, x.Approval, x.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunPass(ctx, passes, 1); err == nil {
		t.Fatal("ordinal executed twice")
	}
	x.Output[0] = 'x'
	if _, err := CheckRetainedPair(x, y); err == nil {
		t.Fatal("mutated output accepted")
	}
	if _, err := (&CompletedPass{}).DataFor(r); err == nil {
		t.Fatal("fabricated capability")
	}
}
