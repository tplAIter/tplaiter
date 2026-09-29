package blockformatter

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var ErrRuntimeUnavailable = errors.New("TRUST_FORMATTER_RUNTIME_UNAVAILABLE")

type RuntimeAdapter struct {
	runtime *trustload.Runtime
	stable  *trustverify.Runtime
	runner  *execx.ApprovedRunner
}
type FormatSelection struct {
	adapter                *RuntimeAdapter
	provider, toolProvider *trustverify.VerifiedResolution
	plan                   Plan
	input                  []byte
	actions                []trustverify.ActionMaterial
}
type PreparedFormat struct {
	selection *FormatSelection
	operation trustverify.OperationInputs
	requests  []trustverify.ExecutionRequest
	materials []*operationtrust.ExecutionMaterial
	used      bool
}
type PendingFormat struct {
	prepared *PreparedFormat
	outputs  [][]byte
	receipts []*execx.ExecutionReceipt
	requests []trustverify.ExecutionRequest
	used     bool
}
type (
	PreparedValidation struct{}
	RuntimeResult      struct {
		adapter          *RuntimeAdapter
		plan             Plan
		input, formatted []byte
		pending          *PendingFormat
	}
)

func NewRuntimeAdapter(runtime *trustload.Runtime) (*RuntimeAdapter, error) {
	if runtime == nil || runtime.TrustRuntime() == nil {
		return nil, ErrRuntimeUnavailable
	}
	r, err := execx.NewApprovedRunner(runtime)
	if err != nil {
		return nil, err
	}
	return &RuntimeAdapter{runtime: runtime, stable: runtime.TrustRuntime(), runner: r}, nil
}

func (a *RuntimeAdapter) Select(ctx context.Context, provider, toolProvider *trustverify.VerifiedResolution, plan Plan, input []byte) (*FormatSelection, error) {
	if a == nil || a.runtime == nil || a.stable == nil || a.runtime.TrustRuntime() != a.stable || provider == nil || toolProvider == nil || ctx == nil || ctx.Err() != nil || plan.Language != "go" || plan.Adapter != "gofmt-stdin-v1" || plan.InputSHA256 != digest(input) || len(input) > maxOutputBytes || plan.Tool.ID != "gofmt" {
		return nil, ErrRuntimeUnavailable
	}
	parsed, err := ParsePlan(mustCanonical(plan))
	if err != nil || parsed.PlanSHA256 != plan.PlanSHA256 {
		return nil, ferr("FORMAT_PLAN", plan.Path)
	}
	if !provider.ValidFor(a.stable, a.stable.Binding()) || !toolProvider.ValidFor(a.stable, a.stable.Binding()) {
		return nil, ErrRuntimeUnavailable
	}
	ids := []string{"format-" + strings.TrimPrefix(plan.PlanSHA256, "sha256:") + "-1", "format-" + strings.TrimPrefix(plan.PlanSHA256, "sha256:") + "-2"}
	p := provider.Subject()
	tp := toolProvider.Subject()
	pm := trustverify.Provider{Origin: p.Origin, TemplatePath: p.TemplatePath, Commit: p.Commit, TreeSHA256: p.TreeSHA256, ContractSHA256: p.ContractSHA256}
	_ = tp
	if reservedRuntimeFormatPath(plan.Path) {
		return nil, ErrRuntimeUnavailable
	}
	planJSON := mustCanonical(plan)
	toolSnapshot, snapshotErr := a.stable.VerifiedSnapshot(toolProvider)
	if snapshotErr != nil || toolSnapshot == nil {
		return nil, ErrRuntimeUnavailable
	}
	record, recordOK := toolSnapshot.Blob("formatter/tool.json")
	if !recordOK {
		return nil, ErrRuntimeUnavailable
	}
	env := operationtrustEnvironment()
	envHash, _ := trustverify.ComputeEnvironmentPolicySHA256(env)
	content := []trustverify.ContentEntry{{Root: "project", Path: plan.Path, Mode: plan.InputMode, ContentSHA256: digestBytes(input)}, {Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: digestBytes(planJSON)}, {Root: "project", Path: "formatter/tool.json", Mode: "100644", ContentSHA256: digestBytes(record)}}
	sort.Slice(content, func(i, j int) bool {
		return content[i].Root+"\x00"+content[i].Path < content[j].Root+"\x00"+content[j].Path
	})
	closure, closureErr := trustverify.ComputeContentClosureSHA256(content)
	if closureErr != nil {
		return nil, ErrRuntimeUnavailable
	}
	actions := make([]trustverify.ActionMaterial, 2)
	for i, id := range ids {
		actions[i] = trustverify.ActionMaterial{Provider: pm, Action: trustverify.Action{ID: id, Kind: "formatter", Phase: "standalone", Shell: false, Argv: append([]string{"gofmt"}, plan.Options...), ContentClosureSHA256: closure}, Tool: plan.Tool, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: envHash, TimeoutMillis: plan.TimeoutMillis, Migration: trustverify.Migration{Kind: "none"}}
	}
	return &FormatSelection{adapter: a, provider: provider, toolProvider: toolProvider, plan: clonePlan(plan), input: append([]byte(nil), input...), actions: actions}, nil
}

func (s *FormatSelection) Actions() []trustverify.ActionMaterial {
	if s == nil {
		return nil
	}
	return cloneActions(s.actions)
}

func (a *RuntimeAdapter) Bind(ctx context.Context, selection *FormatSelection, operation trustverify.OperationInputs) (*PreparedFormat, error) {
	if a == nil || a.runtime == nil || a.runtime.TrustRuntime() != a.stable || selection == nil || selection.adapter != a || ctx == nil || ctx.Err() != nil || len(operation.Actions) == 0 {
		return nil, ErrRuntimeUnavailable
	}
	bindingDigest, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, a.stable.Binding())
	if err != nil || operation.ProfileBindingSHA256 != bindingDigest || operation.ProjectID != a.runtime.ProjectContext().ProjectID {
		return nil, ErrRuntimeUnavailable
	}
	d, err := trustverify.ComputeOperationInputsSHA256(operation)
	if err != nil {
		return nil, ErrRuntimeUnavailable
	}
	toolSubject := providerFromResolution(selection.toolProvider)
	if (operation.Scope != "new" && operation.Scope != "update" && operation.Scope != "run") || !containsProvider(operation.Subjects, selection.actions[0].Provider) || !containsProvider(operation.Subjects, toolSubject) || !uniqueProviders(operation.Subjects) || !uniqueActionIDs(operation.Actions) {
		return nil, ErrRuntimeUnavailable
	}
	requests := make([]trustverify.ExecutionRequest, 2)
	materials := make([]*operationtrust.ExecutionMaterial, 2)
	used := map[string]bool{}
	for i, action := range selection.actions {
		count := 0
		for _, candidate := range operation.Actions {
			if reflect.DeepEqual(candidate, action) {
				count++
			}
		}
		if count != 1 || used[action.Action.ID] {
			return nil, ErrRuntimeUnavailable
		}
		used[action.Action.ID] = true
		requests[i], err = makeRequest(operation, d, action)
		if err != nil {
			return nil, ErrRuntimeUnavailable
		}
		input := operationtrust.FormatterInput{Path: selection.plan.Path, Mode: selection.plan.InputMode, Bytes: selection.input, PlanJSON: mustCanonical(selection.plan)}
		fs, e := operationtrust.ResolveFormatterComposition(ctx, a.stable, selection.provider, selection.toolProvider, operation, action, input)
		if e != nil {
			return nil, e
		}
		materials[i], e = operationtrust.BindFormatterMaterial(ctx, a.stable, selection.provider, selection.toolProvider, operation, action, input, fs)
		if e != nil {
			return nil, e
		}
	}
	return &PreparedFormat{selection: selection, operation: cloneOperation(operation), requests: requests, materials: materials}, nil
}

func (p *PreparedFormat) Requests() []trustverify.ExecutionRequest {
	if p == nil {
		return nil
	}
	return cloneRequests(p.requests)
}

func (a *RuntimeAdapter) Run(ctx context.Context, prepared *PreparedFormat, refs []trustverify.ApprovalRefs) (*PendingFormat, error) {
	if a == nil || a.runtime == nil || a.runtime.TrustRuntime() != a.stable || prepared == nil || prepared.used || len(refs) != len(prepared.requests) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRuntimeUnavailable
	}
	prepared.used = true
	permits := make([]*trustverify.ExecutionPermit, len(prepared.requests))
	for i, req := range prepared.requests {
		permit, err := a.stable.Authorize(ctx, prepared.selection.provider, prepared.operation, req, refs[i])
		if err != nil {
			return nil, err
		}
		if _, err = a.stable.PersistentApprovalReference(permit); err != nil {
			return nil, err
		}
		permits[i] = permit
	}
	receipts := make([]*execx.ExecutionReceipt, len(prepared.requests))
	outputs := make([][]byte, len(prepared.requests))
	for i, req := range prepared.requests {
		var err error
		receipts[i], err = a.runner.Execute(ctx, permits[i], req, prepared.materials[i])
		if err != nil {
			return nil, err
		}
		outputs[i], err = receipts[i].StdoutFor(a.runner, req)
		if err != nil {
			return nil, err
		}
	}
	return &PendingFormat{prepared: prepared, outputs: outputs, receipts: receipts, requests: append([]trustverify.ExecutionRequest(nil), prepared.requests...)}, nil
}

func (p *PendingFormat) ValidationActions() []trustverify.ActionMaterial { return nil }
func (a *RuntimeAdapter) BindValidation(context.Context, *PendingFormat, trustverify.OperationInputs) (*PreparedValidation, error) {
	return nil, ErrRuntimeUnavailable
}

func (a *RuntimeAdapter) Finish(ctx context.Context, pending *PendingFormat, validation *PreparedValidation, refs []trustverify.ApprovalRefs) (*RuntimeResult, error) {
	if a == nil || a.runtime == nil || a.runtime.TrustRuntime() != a.stable || pending == nil || pending.used || validation != nil || len(refs) != 0 || ctx == nil || ctx.Err() != nil || len(pending.outputs) != 2 {
		return nil, ErrRuntimeUnavailable
	}
	pending.used = true
	validator := markerValidator{}
	check, err := CheckOutputs(pending.prepared.selection.plan, pending.prepared.selection.input, pending.outputs[0], pending.outputs[1], validator)
	if err != nil {
		return nil, err
	}
	return &RuntimeResult{adapter: a, plan: clonePlan(pending.prepared.selection.plan), input: append([]byte(nil), pending.prepared.selection.input...), formatted: append([]byte(nil), check.Formatted...), pending: pending}, nil
}

func (r *RuntimeResult) FormattedFor(runtime *trustload.Runtime, plan Plan, input []byte) ([]byte, error) {
	if r == nil || runtime == nil || r.adapter == nil || r.adapter.runtime != runtime || runtime.TrustRuntime() != r.adapter.stable || !reflect.DeepEqual(r.plan, plan) || !bytes.Equal(r.input, input) {
		return nil, ErrRuntimeUnavailable
	}
	return append([]byte(nil), r.formatted...), nil
}

type markerValidator struct{}

func (markerValidator) Validate(language, path string, content []byte) ([]Marker, error) {
	return blockmarkers.Validate(blockmarkers.Language(language), path, content)
}

func operationtrustEnvironment() trustverify.EnvironmentPolicy {
	return trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}, Capabilities: []string{}}
}

func reservedRuntimeFormatPath(path string) bool {
	folded := strings.ToLower(path)
	return folded == "formatter" || strings.HasPrefix(folded, "formatter/") || folded == "native-tool" || folded == ".tplaiter-execution" || strings.HasPrefix(folded, ".tplaiter-execution/")
}
func digestBytes(b []byte) string { return digest(b) }
func providerFromResolution(r *trustverify.VerifiedResolution) trustverify.Provider {
	s := r.Subject()
	return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func containsProvider(xs []trustverify.Provider, want trustverify.Provider) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func uniqueProviders(xs []trustverify.Provider) bool {
	seen := make(map[trustverify.Provider]struct{}, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			return false
		}
		seen[x] = struct{}{}
	}
	return true
}

func uniqueActionIDs(xs []trustverify.ActionMaterial) bool {
	seen := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x.Action.ID == "" {
			return false
		}
		if _, ok := seen[x.Action.ID]; ok {
			return false
		}
		seen[x.Action.ID] = struct{}{}
	}
	return true
}

func cloneActions(xs []trustverify.ActionMaterial) []trustverify.ActionMaterial {
	out := append([]trustverify.ActionMaterial(nil), xs...)
	for i := range out {
		out[i].Action.Argv = append([]string(nil), out[i].Action.Argv...)
	}
	return out
}

func cloneOperation(o trustverify.OperationInputs) trustverify.OperationInputs {
	o.Subjects = append([]trustverify.Provider(nil), o.Subjects...)
	o.Actions = cloneActions(o.Actions)
	return o
}

func cloneRequests(xs []trustverify.ExecutionRequest) []trustverify.ExecutionRequest {
	out := append([]trustverify.ExecutionRequest(nil), xs...)
	for i := range out {
		out[i].Action.Argv = append([]string(nil), out[i].Action.Argv...)
	}
	return out
}

func makeRequest(op trustverify.OperationInputs, digest string, a trustverify.ActionMaterial) (trustverify.ExecutionRequest, error) {
	r := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: op.ProfileBindingSHA256, OperationInputsSHA256: digest, ProjectID: op.ProjectID, Scope: op.Scope, Provider: a.Provider, Action: a.Action, Tool: a.Tool, WorkingDirectoryScope: a.WorkingDirectoryScope, EnvironmentPolicySHA256: a.EnvironmentPolicySHA256, TimeoutMillis: a.TimeoutMillis, Migration: a.Migration}
	d, e := r.ComputeRequestSHA256()
	r.RequestSHA256 = d
	return r, e
}
