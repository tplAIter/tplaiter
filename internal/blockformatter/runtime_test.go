package blockformatter

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"os"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestRuntimeActionIdentityHelpersRejectDuplicates(t *testing.T) {
	a := trustverify.ActionMaterial{Action: trustverify.Action{ID: "format-a"}}
	if !uniqueActionIDs([]trustverify.ActionMaterial{a}) {
		t.Fatal("unique action rejected")
	}
	if uniqueActionIDs([]trustverify.ActionMaterial{a, a}) {
		t.Fatal("duplicate action ID accepted")
	}
	if uniqueActionIDs([]trustverify.ActionMaterial{{}}) {
		t.Fatal("empty action ID accepted")
	}
}

func TestRequestsAccessorCopiesArguments(t *testing.T) {
	p := &PreparedFormat{requests: []trustverify.ExecutionRequest{{Action: trustverify.Action{Argv: []string{"gofmt"}}}}}
	got := p.Requests()
	got[0].Action.Argv[0] = "changed"
	if p.requests[0].Action.Argv[0] != "gofmt" {
		t.Fatal("Requests leaked mutable argv")
	}
}

func TestFormatterPairRejectsSequentialSecondPass(t *testing.T) {
	input := []byte("package fixture\n")
	plan, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: formatterTool(t, []string{}), Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	format := func(data []byte) []byte { return append(append([]byte(nil), data...), []byte("// pass\n")...) }
	first, independent, sequential := format(input), format(input), format(format(input))
	if bytes.Equal(first, sequential) {
		t.Fatal("counterexample must be non-idempotent")
	}
	if _, err := CheckOutputs(plan, input, first, independent, markerValidator{}); err != nil {
		t.Fatalf("independent F(original) outputs: %v", err)
	}
	if _, err := CheckOutputs(plan, input, first, sequential, markerValidator{}); materialCode(err) != "FORMAT_NONDETERMINISTIC" {
		t.Fatalf("F(F(original)) accepted: %v", err)
	}
}

func TestSequentialSecondPassCanHideNondeterminism(t *testing.T) {
	input := []byte("package fixture\n")
	plan, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: formatterTool(t, []string{}), Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	y, z := append(append([]byte(nil), input...), []byte("// first\n")...), append(append([]byte(nil), input...), []byte("// second\n")...)
	originalCalls := 0
	format := func(data []byte) []byte {
		if bytes.Equal(data, input) {
			originalCalls++
			if originalCalls == 1 {
				return append([]byte(nil), y...)
			}
			return append([]byte(nil), z...)
		}
		if bytes.Equal(data, y) {
			return append([]byte(nil), y...)
		}
		t.Fatal("unexpected formatter input")
		return nil
	}
	first := format(input)
	sequential := format(first)
	if _, err := CheckOutputs(plan, input, first, sequential, markerValidator{}); err != nil {
		t.Fatalf("sequential F(F(x)) should misleadingly pass: %v", err)
	}
	independent := format(input)
	if bytes.Equal(first, independent) {
		t.Fatal("counterexample must produce different independent outputs")
	}
	if _, err := CheckOutputs(plan, input, first, independent, markerValidator{}); materialCode(err) != "FORMAT_NONDETERMINISTIC" {
		t.Fatalf("paired F(x) failed to detect nondeterminism: %v", err)
	}
}

func TestRuntimeAdapterSignedGofmtPair(t *testing.T) {
	if goruntime.GOOS != "darwin" || goruntime.GOARCH != "arm64" {
		t.Skip("the pinned native gofmt proof requires Darwin arm64")
	}
	f := testfixture.NewGofmtFixture(t)
	runtime, resolution := f.Open(t)
	adapter, err := NewRuntimeAdapter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	input := []byte("package fixture\nfunc f(){ }\n")
	opts, err := trustverify.ComputeToolOptionsSHA256([]string{})
	if err != nil {
		t.Fatal(err)
	}
	tool := trustverify.Tool{ID: "gofmt", Version: strings.TrimPrefix(runtimeGoVersion(t, f.Tool()), "go"), BinarySHA256: evidencecas.Digest(f.Tool()), OptionsSHA256: opts}
	plan, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := adapter.Select(ctx, resolution, resolution, plan, input)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(selection.Actions()) != 2 || selection.Actions()[0].Action.ID == selection.Actions()[1].Action.ID {
		t.Fatal("pair identity")
	}
	profile, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, runtime.TrustRuntime().Binding())
	if err != nil {
		t.Fatal(err)
	}
	provider := providerFromResolution(resolution)
	otherSubject := provider
	otherSubject.Origin = "https://z.example.test/other-source"
	operation := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: profile, ProjectID: runtime.ProjectContext().ProjectID, Scope: "run", PreimageSHA256: evidencecas.Digest([]byte("preimage")), AnswersSHA256: evidencecas.Digest([]byte("{}")), Subjects: []trustverify.Provider{provider, otherSubject}, Actions: selection.Actions()}
	extra := selection.Actions()[0]
	extra.Action.ID = "caller-other-file-action"
	extra.Provider = otherSubject
	operation.Actions = append(operation.Actions, extra)
	fullDigest, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := adapter.Bind(ctx, selection, operation)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	requests := prepared.Requests()
	if len(requests) != 2 || requests[0].RequestSHA256 == requests[1].RequestSHA256 || requests[0].OperationInputsSHA256 != fullDigest || requests[1].OperationInputsSHA256 != fullDigest {
		t.Fatal("requests must bind two distinct actions in the complete caller operation")
	}
	omitted := operation
	omitted.Actions = []trustverify.ActionMaterial{selection.Actions()[0], extra}
	if _, err := adapter.Bind(ctx, selection, omitted); err == nil {
		t.Fatal("missing second selected action bound")
	}
	duplicated := operation
	duplicated.Actions = append(append([]trustverify.ActionMaterial(nil), operation.Actions...), selection.Actions()[0])
	if _, err := adapter.Bind(ctx, selection, duplicated); err == nil {
		t.Fatal("duplicate selected action bound")
	}
	missingSubject := operation
	missingSubject.Subjects = []trustverify.Provider{otherSubject}
	if _, err := adapter.Bind(ctx, selection, missingSubject); err == nil {
		t.Fatal("required provider subject omitted")
	}
	duplicateSubject := operation
	duplicateSubject.Subjects = []trustverify.Provider{provider, provider, otherSubject}
	if _, err := adapter.Bind(ctx, selection, duplicateSubject); err == nil {
		t.Fatal("duplicate provider subject bound")
	}
	for i, request := range requests {
		staged, err := prepared.materials[i].StagedFor(ctx, runtime.TrustRuntime(), request)
		if err != nil {
			t.Fatalf("StagedFor[%d]: %v", i, err)
		}
		if staged.Request.RequestSHA256 != request.RequestSHA256 || staged.Operation.ProjectID != operation.ProjectID || staged.Request.Action.ID != selection.Actions()[i].Action.ID {
			t.Fatalf("staged[%d] lost operation or request binding", i)
		}
		foundInput, foundPlan, foundRecord := false, false, false
		for j, entry := range staged.Content {
			switch entry.Path {
			case plan.Path:
				foundInput = bytes.Equal(staged.ContentBytes[j], input)
			case "formatter/plan.json":
				foundPlan = bytes.Equal(staged.ContentBytes[j], mustCanonical(plan))
			case "formatter/tool.json":
				foundRecord = bytes.Equal(staged.ContentBytes[j], f.Record())
			}
		}
		if !foundInput || !foundPlan || !foundRecord || !bytes.Equal(staged.ToolBytes, f.Tool()) {
			t.Fatalf("staged[%d] lacks original signed input, plan, record, or binary", i)
		}
	}
	refs := []trustverify.ApprovalRefs{f.Approval(t, requests[0]), f.Approval(t, requests[1])}
	if refs[0].ApprovalCAS == refs[1].ApprovalCAS {
		t.Fatal("distinct persistent approvals required")
	}
	badOperation := operation
	badOperation.ProjectID = "other-project"
	if _, err := adapter.Bind(ctx, selection, badOperation); err == nil {
		t.Fatal("wrong project bound")
	}
	badOperation = operation
	badOperation.ProfileBindingSHA256 = evidencecas.Digest([]byte("other-binding"))
	if _, err := adapter.Bind(ctx, selection, badOperation); err == nil {
		t.Fatal("wrong profile bound")
	}
	badOperation = operation
	badOperation.Scope = "migration"
	if _, err := adapter.Bind(ctx, selection, badOperation); err == nil {
		t.Fatal("formatter bound outside new/update/run scope")
	}
	badPlan := plan
	badPlan.OutputLimitBytes++
	if _, err := adapter.Select(ctx, resolution, resolution, badPlan, input); err == nil {
		t.Fatal("changed plan selected")
	}
	if _, err := adapter.Select(ctx, resolution, resolution, plan, []byte("package changed\n")); err == nil {
		t.Fatal("candidate bytes changed after plan")
	}
	driftedTool := tool
	driftedTool.BinarySHA256 = evidencecas.Digest([]byte("different signed tool"))
	driftedPlan, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: driftedTool, Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	driftedSelection, err := adapter.Select(ctx, resolution, resolution, driftedPlan, input)
	if err != nil {
		t.Fatal(err)
	}
	driftedOperation := operation
	driftedOperation.Actions = driftedSelection.Actions()
	if _, err := adapter.Bind(ctx, driftedSelection, driftedOperation); err == nil {
		t.Fatal("tool digest drift bound against signed record")
	}
	for _, path := range []string{"formatter/native-tool", "Formatter/plan.json", "FORMATTER/tool.json", "native-tool", ".tplaiter-execution/stdin"} {
		colliding, err := BuildPlan(PlanInput{Path: path, Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.Select(ctx, resolution, resolution, colliding, input); err == nil {
			t.Fatalf("reserved path %q selected", path)
		}
	}
	if _, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{"-w"}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input}); err == nil {
		t.Fatal("gofmt write option accepted")
	}
	rejected, err := adapter.Bind(ctx, selection, operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Run(ctx, rejected, []trustverify.ApprovalRefs{refs[0], {Kind: "persistent-signed", ApprovalCAS: refs[0].ApprovalCAS}}); err == nil {
		t.Fatal("second action accepted first action's approval")
	}
	if entries, err := os.ReadDir(f.Scratch()); err != nil || len(entries) != 0 {
		t.Fatalf("second approval rejection spawned or leaked files: %v, %v", entries, err)
	}
	pending, err := adapter.Run(ctx, prepared, refs)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pending.receipts) != 2 || !bytes.Equal(pending.outputs[0], pending.outputs[1]) || bytes.Equal(input, pending.outputs[0]) {
		t.Fatal("two same-original formatting receipts required")
	}
	result, err := adapter.Finish(ctx, pending, nil, nil)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	formatted, err := result.FormattedFor(runtime, plan, input)
	if err != nil || !bytes.Equal(formatted, []byte("package fixture\n\nfunc f() {}\n")) {
		t.Fatalf("FormattedFor = %q, %v", formatted, err)
	}
	if _, err := result.FormattedFor(runtime, plan, formatted); err == nil {
		t.Fatal("F(F(x)) input accepted as original")
	}
	if _, err := result.FormattedFor(runtime, badPlan, input); err == nil {
		t.Fatal("changed plan accepted by result")
	}
	runVariant := func(p Plan) (*PendingFormat, error) {
		t.Helper()
		selected, err := adapter.Select(ctx, resolution, resolution, p, input)
		if err != nil {
			t.Fatal(err)
		}
		variantOperation := operation
		variantOperation.Actions = selected.Actions()
		bound, err := adapter.Bind(ctx, selected, variantOperation)
		if err != nil {
			t.Fatal(err)
		}
		r := bound.Requests()
		return adapter.Run(ctx, bound, []trustverify.ApprovalRefs{f.Approval(t, r[0]), f.Approval(t, r[1])})
	}
	capped, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: []Marker{}, TimeoutMillis: 5000, OutputLimitBytes: 1, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	capPending, err := runVariant(capped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Finish(ctx, capPending, nil, nil); materialCode(err) != "FORMAT_OUTPUT_LIMIT" {
		t.Fatalf("output cap: %v", err)
	}
	marked, err := BuildPlan(PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: []Marker{{Kind: "begin", ID: "marker", Provider: "fixture"}, {Kind: "end", ID: "marker"}}, TimeoutMillis: 5000, OutputLimitBytes: 1 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	markerPending, err := runVariant(marked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Finish(ctx, markerPending, nil, nil); materialCode(err) != "FORMAT_MARKER" {
		t.Fatalf("marker drift: %v", err)
	}
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	timeoutSelection, err := adapter.Select(ctx, resolution, resolution, plan, input)
	if err != nil {
		t.Fatal(err)
	}
	timeoutPrepared, err := adapter.Bind(ctx, timeoutSelection, operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Run(expired, timeoutPrepared, refs); err == nil {
		t.Fatal("expired context ran formatter")
	}
	source := resolution.Subject()
	t.Logf("signed gofmt evidence sourceCommit=%s sourceTree=%s sourceContract=%s toolBinary=%s toolRecord=%s plan=%s fullOperation=%s request1=%s request2=%s approval1=%s approval2=%s output1=%s output2=%s", source.Commit, source.TreeSHA256, source.ContractSHA256, tool.BinarySHA256, evidencecas.Digest(f.Record()), plan.PlanSHA256, fullDigest, requests[0].RequestSHA256, requests[1].RequestSHA256, refs[0].ApprovalCAS, refs[1].ApprovalCAS, evidencecas.Digest(pending.outputs[0]), evidencecas.Digest(pending.outputs[1]))
	driftPrepared, err := adapter.Bind(ctx, selection, operation)
	if err != nil {
		t.Fatal(err)
	}
	f.CorruptSignedToolRecord(t)
	if _, err := driftPrepared.materials[0].StagedFor(ctx, runtime.TrustRuntime(), driftPrepared.Requests()[0]); err == nil {
		t.Fatal("changed signed tool source staged from retained resolution")
	}
	if _, err := adapter.Run(ctx, driftPrepared, refs); err == nil {
		t.Fatal("changed signed tool source executed")
	}
	if entries, err := os.ReadDir(f.Scratch()); err != nil || len(entries) != 0 {
		t.Fatalf("drift left scratch residue: %v, %v", entries, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := result.FormattedFor(runtime, plan, input); err == nil {
		t.Fatal("closed runtime accepted by result")
	}
	if _, err := adapter.Select(ctx, resolution, resolution, plan, input); err == nil {
		t.Fatal("closed runtime selected")
	}
	if _, err := adapter.Bind(ctx, selection, operation); err == nil {
		t.Fatal("closed runtime bound")
	}
	if entries, err := os.ReadDir(f.Scratch()); err != nil || len(entries) != 0 {
		t.Fatalf("scratch residue: %v, %v", entries, err)
	}
	if entries, err := os.ReadDir(f.Project()); err != nil || len(entries) != 0 {
		t.Fatalf("project write residue: %v, %v", entries, err)
	}
}

func runtimeGoVersion(t *testing.T, tool []byte) string {
	t.Helper()
	info, err := buildinfo.Read(bytes.NewReader(tool))
	if err != nil || info.Path != "cmd/gofmt" {
		t.Fatalf("gofmt buildinfo: %v, %#v", err, info)
	}
	return info.GoVersion
}
