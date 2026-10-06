package operationtrust

// This file is the deliberately finite bridge from an authenticated native
// snapshot to the approved Darwin runner.  It has no path or callback input.

import (
	"context"
	"errors"
	"reflect"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	executionDir = ".tplaiter-execution"
	toolPath     = executionDir + "/native-tool"
	stdinPath    = executionDir + "/stdin"
)

var ErrExecutionMaterialUnavailable = errors.New("TRUST_EXECUTION_MATERIAL_UNAVAILABLE")

type FixedCompositionSelection struct {
	runtime     *trustverify.Runtime
	resolution  *trustverify.VerifiedResolution
	operation   trustverify.OperationInputs
	request     trustverify.ExecutionRequest
	tool, stdin []byte
}

type ExecutionMaterial struct {
	batchAction    *batchActionSelection
	batchApprovals []string
	action         *ActionSelection
	selection      *FixedCompositionSelection
	formatter      *FormatterSelection
	projectBuild   *ProjectBuildSelection
}

func ResolveFixedComposition(ctx context.Context, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, operation trustverify.OperationInputs, request trustverify.ExecutionRequest) (*FixedCompositionSelection, error) {
	if ctx == nil || ctx.Err() != nil || runtime == nil || resolution == nil || request.VerifyRequestSHA256() != nil || !resolution.ValidFor(runtime, runtime.Binding()) {
		return nil, ErrExecutionMaterialUnavailable
	}
	bindingDigest, bindingErr := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, runtime.Binding())
	if bindingErr != nil || operation.ProfileBindingSHA256 != request.ProfileBindingSHA256 || request.ProfileBindingSHA256 != bindingDigest || operation.ProjectID != request.ProjectID || operation.Scope != request.Scope {
		return nil, ErrExecutionMaterialUnavailable
	}
	if d, err := trustverify.ComputeOperationInputsSHA256(operation); err != nil || d != request.OperationInputsSHA256 || len(operation.Subjects) != 1 || len(operation.Actions) != 1 {
		return nil, ErrExecutionMaterialUnavailable
	}
	s, err := runtime.VerifiedSnapshot(resolution)
	if err != nil || s == nil {
		return nil, ErrExecutionMaterialUnavailable
	}
	// The execution convention adds bytes to an otherwise native snapshot; it
	// must not bypass the pre-existing contract/manifest closure.
	manifest, ok := s.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrExecutionMaterialUnavailable
	}
	if _, err := requireNativeContract(s.ContractBytes(), manifest); err != nil {
		return nil, ErrExecutionMaterialUnavailable
	}
	if !reflect.DeepEqual(request.Provider, provider(s.Subject())) || !reflect.DeepEqual(operation.Subjects[0], request.Provider) || !reflect.DeepEqual(operation.Actions[0], actionMaterial(request)) {
		return nil, ErrExecutionMaterialUnavailable
	}
	if request.Scope != "run" || request.Action.Kind != "command" || request.Action.Phase != "standalone" || request.Action.Shell || request.Action.ID == "" || !reflect.DeepEqual(request.Action.Argv, []string{"native-snapshot-tool-v1"}) || request.Tool.ID != "native-snapshot-tool-v1" || request.Tool.Version != "1" || request.WorkingDirectoryScope != (trustverify.WorkingDirectoryScope{Root: "provider", Path: executionDir}) || request.TimeoutMillis < 1 || request.TimeoutMillis > 5000 || request.Migration.Kind != "none" {
		return nil, ErrExecutionMaterialUnavailable
	}
	entries := s.Entries()
	want := map[string]struct{}{executionDir: {}, toolPath: {}, stdinPath: {}}
	found := map[string]trustverify.SourceEntry{}
	for _, e := range entries {
		if e.Path == executionDir || len(e.Path) > len(executionDir) && e.Path[:len(executionDir)+1] == executionDir+"/" {
			found[e.Path] = e
		}
	}
	if len(found) != 3 {
		return nil, ErrExecutionMaterialUnavailable
	}
	if e := found[executionDir]; e.Kind != "directory" || e.Mode != "40000" {
		return nil, ErrExecutionMaterialUnavailable
	}
	for p := range want {
		if _, ok := found[p]; !ok {
			return nil, ErrExecutionMaterialUnavailable
		}
	}
	if e := found[toolPath]; e.Kind != "file" || e.Mode != "100755" {
		return nil, ErrExecutionMaterialUnavailable
	}
	if e := found[stdinPath]; e.Kind != "file" || e.Mode != "100644" {
		return nil, ErrExecutionMaterialUnavailable
	}
	tool, ok := s.Blob(toolPath)
	if !ok || len(tool) == 0 || len(tool) > 16<<20 || evidencecas.Digest(tool) != found[toolPath].ContentSHA256 || evidencecas.Digest(tool) != request.Tool.BinarySHA256 {
		return nil, ErrExecutionMaterialUnavailable
	}
	stdin, ok := s.Blob(stdinPath)
	if !ok || len(stdin) > 1<<20 || evidencecas.Digest(stdin) != found[stdinPath].ContentSHA256 {
		return nil, ErrExecutionMaterialUnavailable
	}
	content := []trustverify.ContentEntry{{Root: "provider", Path: stdinPath, Mode: "100644", ContentSHA256: evidencecas.Digest(stdin)}}
	closure, e := trustverify.ComputeContentClosureSHA256(content)
	if e != nil || closure != request.Action.ContentClosureSHA256 {
		return nil, ErrExecutionMaterialUnavailable
	}
	options, e := trustverify.ComputeToolOptionsSHA256([]string{})
	env, e2 := trustverify.ComputeEnvironmentPolicySHA256(fixedEnvironment())
	if e != nil || e2 != nil || request.Tool.OptionsSHA256 != options || request.EnvironmentPolicySHA256 != env {
		return nil, ErrExecutionMaterialUnavailable
	}
	return &FixedCompositionSelection{runtime: runtime, resolution: resolution, operation: cloneOperation(operation), request: cloneRequest(request), tool: append([]byte(nil), tool...), stdin: append([]byte(nil), stdin...)}, nil
}

func BindExecutionMaterial(ctx context.Context, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, operation trustverify.OperationInputs, request trustverify.ExecutionRequest, s *FixedCompositionSelection) (*ExecutionMaterial, error) {
	if s == nil || s.runtime != runtime || s.resolution != resolution || !reflect.DeepEqual(s.operation, operation) || !reflect.DeepEqual(s.request, request) {
		return nil, ErrExecutionMaterialUnavailable
	}
	again, e := ResolveFixedComposition(ctx, runtime, resolution, operation, request)
	if e != nil || !reflect.DeepEqual(again.tool, s.tool) || !reflect.DeepEqual(again.stdin, s.stdin) {
		return nil, ErrExecutionMaterialUnavailable
	}
	return &ExecutionMaterial{selection: s}, nil
}

func (m *ExecutionMaterial) StagedFor(ctx context.Context, runtime *trustverify.Runtime, request trustverify.ExecutionRequest) (trustverify.StagedMaterial, error) {
	if m != nil && m.action != nil {
		if m.action.stable != runtime {
			return trustverify.StagedMaterial{}, ErrActionSelection
		}
		staged, _, err := m.ActionFor(ctx, m.action.owner, request)
		return staged, err
	}
	if m != nil && m.projectBuild != nil {
		if ctx == nil || m.projectBuild.owner == nil || m.projectBuild.owner.TrustRuntime() != runtime {
			return trustverify.StagedMaterial{}, ErrExecutionMaterialUnavailable
		}
		staged, _, err := m.ProjectBuildFor(ctx, m.projectBuild.owner, request)
		return staged, err
	}
	if m != nil && m.formatter != nil {
		return m.stagedFormatter(ctx, runtime, request)
	}
	if ctx == nil || ctx.Err() != nil || m == nil || m.selection == nil || m.selection.runtime != runtime || !reflect.DeepEqual(m.selection.request, request) {
		return trustverify.StagedMaterial{}, ErrExecutionMaterialUnavailable
	}
	s := m.selection
	return trustverify.StagedMaterial{Operation: cloneOperation(s.operation), Request: cloneRequest(s.request), Content: []trustverify.ContentEntry{{Root: "provider", Path: stdinPath, Mode: "100644", ContentSHA256: evidencecas.Digest(s.stdin)}}, ContentBytes: [][]byte{append([]byte(nil), s.stdin...)}, ToolBytes: append([]byte(nil), s.tool...), ToolOptions: []string{}, Environment: fixedEnvironment()}, nil
}

func BindActionMaterial(ctx context.Context, owner *trustload.Runtime, s *ActionSelection) (*ExecutionMaterial, error) {
	if s == nil || s.closed || s.owner != owner {
		return nil, ErrActionSelection
	}
	if err := s.Recheck(ctx, owner); err != nil {
		return nil, err
	}
	return &ExecutionMaterial{action: s}, nil
}

func (m *ExecutionMaterial) ActionFor(ctx context.Context, owner *trustload.Runtime, request trustverify.ExecutionRequest) (trustverify.StagedMaterial, ActionProjection, error) {
	if m != nil && m.batchAction != nil {
		return m.batchAction.staged(ctx, owner, request)
	}
	if m == nil || m.action == nil || m.action.closed || m.action.owner != owner || request.VerifyRequestSHA256() != nil || !reflect.DeepEqual(request, m.action.request) {
		return trustverify.StagedMaterial{}, ActionProjection{}, ErrActionSelection
	}
	s := m.action
	if err := s.Recheck(ctx, owner); err != nil {
		return trustverify.StagedMaterial{}, ActionProjection{}, err
	}
	data := make([][]byte, len(s.contentBytes))
	for i, b := range s.contentBytes {
		data[i] = append([]byte(nil), b...)
	}
	p := s.projection
	p.Stdin = append([]byte(nil), p.Stdin...)
	p.Files = append([]ActionInputFile(nil), p.Files...)
	for i := range p.Files {
		p.Files[i].Bytes = append([]byte(nil), p.Files[i].Bytes...)
	}
	return trustverify.StagedMaterial{Operation: s.Operation(), Request: s.Request(), Content: append([]trustverify.ContentEntry(nil), s.content...), ContentBytes: data, ToolBytes: append([]byte(nil), s.tool...), ToolOptions: nativeActionToolOptions(request.Action.Argv), Environment: fixedEnvironment()}, p, nil
}

func (m *ExecutionMaterial) ActionInputFor(owner *trustload.Runtime, request trustverify.ExecutionRequest) (ActionInput, error) {
	if m != nil && m.batchAction != nil {
		s := m.batchAction
		if s.batch.closed || s.batch.owner != owner || !reflect.DeepEqual(s.request, request) {
			return ActionInput{}, ErrRunBatch
		}
		x := s.original.input
		x.ParametersJSON = append([]byte(nil), x.ParametersJSON...)
		return x, nil
	}
	if m == nil || m.action == nil || m.action.closed || m.action.owner != owner || !reflect.DeepEqual(m.action.request, request) {
		return ActionInput{}, ErrActionSelection
	}
	x := m.action.input
	x.ParametersJSON = append([]byte(nil), x.ParametersJSON...)
	return x, nil
}

func (m *ExecutionMaterial) CloseAction(owner *trustload.Runtime) {
	if m != nil && m.batchAction != nil && m.batchAction.batch.owner == owner {
		m.batchAction.batch.Close()
		return
	}
	if m != nil && m.action != nil && m.action.owner == owner {
		m.action.Close()
	}
}

func fixedEnvironment() trustverify.EnvironmentPolicy {
	return trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}, Capabilities: []string{}}
}

func provider(s trustverify.Subject) trustverify.Provider {
	return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func actionMaterial(r trustverify.ExecutionRequest) trustverify.ActionMaterial {
	return trustverify.ActionMaterial{Provider: r.Provider, Action: r.Action, Tool: r.Tool, WorkingDirectoryScope: r.WorkingDirectoryScope, EnvironmentPolicySHA256: r.EnvironmentPolicySHA256, TimeoutMillis: r.TimeoutMillis, Migration: r.Migration}
}

func cloneRequest(r trustverify.ExecutionRequest) trustverify.ExecutionRequest {
	r.Action.Argv = append([]string(nil), r.Action.Argv...)
	return r
}

func cloneOperation(o trustverify.OperationInputs) trustverify.OperationInputs {
	o.Subjects = append([]trustverify.Provider(nil), o.Subjects...)
	o.Actions = append([]trustverify.ActionMaterial(nil), o.Actions...)
	for i := range o.Actions {
		o.Actions[i].Action.Argv = append([]string(nil), o.Actions[i].Action.Argv...)
	}
	return o
}

func nativeActionToolOptions(argv []string) []string { return append([]string{}, argv[1:]...) }

func (m *ExecutionMaterial) ActionBatchFor(owner *trustload.Runtime, request trustverify.ExecutionRequest) (RunBatchInput, int, []string, bool, error) {
	if m == nil {
		return RunBatchInput{}, 0, nil, false, ErrRunBatch
	}
	if m.batchAction == nil {
		return RunBatchInput{}, 0, nil, false, nil
	}
	s := m.batchAction
	if s.batch.closed || s.batch.owner != owner || !reflect.DeepEqual(s.request, request) || len(m.batchApprovals) != len(s.batch.selections) {
		return RunBatchInput{}, 0, nil, false, ErrRunBatch
	}
	return s.batch.Input(), s.ordinal, append([]string(nil), m.batchApprovals...), true, nil
}
