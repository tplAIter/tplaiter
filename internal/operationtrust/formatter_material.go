package operationtrust

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextauth"
	"github.com/tplAIter/tplaiter/internal/contextwire"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var ErrFormatterMaterialUnavailable = errors.New("TRUST_FORMATTER_MATERIAL_UNAVAILABLE")

type FormatterSelection struct {
	mergedCalculation                     *ContextUpdateMergedFormatterCalculation
	updateCalculation                     *ContextUpdateFormatterCalculation
	installed                             *trustload.Runtime
	sources                               *contextauth.VerifiedSourceClosure
	calculation                           *ContextNewFormatterCalculation
	runtime, providerRuntime, toolRuntime *trustverify.Runtime
	provider, toolProvider                *trustverify.VerifiedResolution
	operation                             trustverify.OperationInputs
	action                                trustverify.ActionMaterial
	tool, input, plan, record, context    []byte
	path, mode                            string
}

// FormatterInput carries sealed data only. It cannot select a binary, a
// runner, a source resolution, or a filesystem location outside the fixed
// logical formatter projection.
type FormatterInput struct {
	Path, Mode  string
	Bytes       []byte
	PlanJSON    []byte
	ContextJSON []byte
}

// ManagedFormatterContext binds a finite lifecycle projection to both formatter
// requests. It is data only; it carries no permit or executable selection.
type ManagedFormatterContext struct {
	APIVersion                    string `json:"apiVersion"`
	Role                          string `json:"role"`
	SourceRootLockSHA256          string `json:"sourceRootLockSHA256"`
	TargetRootLockSHA256          string `json:"targetRootLockSHA256"`
	ReplacementDeclarationsSHA256 string `json:"replacementDeclarationsSHA256"`
	DecisionsSHA256               string `json:"decisionsSHA256"`
	ObservedProjectSHA256         string `json:"observedProjectSHA256"`
	ObservedRegistrySHA256        string `json:"observedRegistrySHA256"`
	RendererAnswersSHA256         string `json:"rendererAnswersSHA256"`
	PredecessorCleanProofSHA256   string `json:"predecessorCleanProofSHA256,omitempty"`
}

func ParseManagedFormatterContext(raw []byte) (ManagedFormatterContext, error) {
	var c ManagedFormatterContext
	if len(raw) == 0 || len(raw) > 1<<20 || canonicaljson.DecodeStrict(raw, &c) != nil {
		return c, ErrFormatterMaterialUnavailable
	}
	canonical, err := canonicaljson.Canonical(c)
	if err != nil || !bytes.Equal(raw, canonical) || c.APIVersion != "tplaiter.dev/managed-formatter-context/v1" || (c.Role != "clean-target" && c.Role != "merged-candidate") {
		return ManagedFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	for _, d := range []string{c.SourceRootLockSHA256, c.TargetRootLockSHA256, c.ReplacementDeclarationsSHA256, c.DecisionsSHA256, c.ObservedProjectSHA256, c.ObservedRegistrySHA256, c.RendererAnswersSHA256} {
		if !formatterDigest(d) {
			return ManagedFormatterContext{}, ErrFormatterMaterialUnavailable
		}
	}
	if (c.Role == "merged-candidate" && !formatterDigest(c.PredecessorCleanProofSHA256)) || (c.Role == "clean-target" && c.PredecessorCleanProofSHA256 != "") {
		return ManagedFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	return c, nil
}

func formatterDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") || strings.ToLower(d) != d {
		return false
	}
	_, err := hex.DecodeString(d[7:])
	return err == nil
}

const (
	formatterToolRecordPath = "formatter/tool.json"
	formatterToolBinaryPath = "formatter/native-tool"
)

// formatterToolRecord is deliberately a closed, signed source record. The
// executable bytes are never selected by a host path or a caller callback.
type formatterToolRecord struct {
	APIVersion      string                   `json:"apiVersion"`
	Adapter         string                   `json:"adapter"`
	ToolID          string                   `json:"toolID"`
	ToolVersion     string                   `json:"toolVersion"`
	BinarySHA256    string                   `json:"binarySHA256"`
	VersionEvidence formatterVersionEvidence `json:"versionEvidence"`
	NativeEnvelope  string                   `json:"nativeEnvelope"`
}

type formatterVersionEvidence struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
}

func ResolveFormatterComposition(ctx context.Context, runtime *trustverify.Runtime, provider, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	if ctx == nil || ctx.Err() != nil || runtime == nil || provider == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	snapshot, err := runtime.VerifiedSnapshot(provider)
	if err != nil || snapshot == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, err := requireNativeContract(snapshot.ContractBytes(), mustBlob(snapshot, "template.manifest.yaml")); err != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	if len(input.ContextJSON) > 0 {
		if _, err := ParseManagedFormatterContext(input.ContextJSON); err != nil {
			return nil, err
		}
	}
	return resolveFormatterTool(ctx, runtime, provider, toolProvider, operation, action, input)
}

func resolveFormatterTool(ctx context.Context, runtime *trustverify.Runtime, provider, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	if ctx == nil || ctx.Err() != nil || runtime == nil || provider == nil || toolProvider == nil || len(input.Bytes) > 16<<20 || len(input.PlanJSON) == 0 || len(input.PlanJSON) > 1<<20 || input.Path == "" || reservedFormatterInputPath(input.Path) || input.Mode != "100644" || !provider.ValidFor(runtime, runtime.Binding()) || !toolProvider.ValidFor(runtime, runtime.Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	if action.Action.Kind != "formatter" || action.Action.Phase != "standalone" || action.Action.Shell || !reflect.DeepEqual(action.Action.Argv, []string{"gofmt"}) || action.Tool.Validate() != nil || action.Tool.ID != "gofmt" || action.TimeoutMillis < 1 || action.TimeoutMillis > 120000 || action.WorkingDirectoryScope != (trustverify.WorkingDirectoryScope{Root: "project", Path: "."}) {
		return nil, ErrFormatterMaterialUnavailable
	}
	ps, err := runtime.VerifiedSnapshot(provider)
	if err != nil || ps == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	ts, err := runtime.VerifiedSnapshot(toolProvider)
	if err != nil || ts == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, ok := ps.Blob("template.manifest.yaml"); !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	recordBytes, ok := ts.Blob(formatterToolRecordPath)
	if !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	record, err := parseFormatterToolRecord(recordBytes)
	if err != nil || record.Adapter != "gofmt-stdin-v1" || record.ToolID != "gofmt" || record.ToolVersion != action.Tool.Version || record.BinarySHA256 != action.Tool.BinarySHA256 || record.NativeEnvelope == "" || record.NativeEnvelope != FormatterNativeEnvelope() {
		return nil, ErrFormatterMaterialUnavailable
	}
	if record.VersionEvidence.Kind != "go-buildinfo" {
		return nil, ErrFormatterMaterialUnavailable
	}
	tool, ok := ts.Blob(formatterToolBinaryPath)
	if !ok || len(tool) == 0 || len(tool) > 16<<20 || evidencecas.Digest(tool) != action.Tool.BinarySHA256 || !formatterToolEntry(ts.Entries(), action.Tool.BinarySHA256) {
		return nil, ErrFormatterMaterialUnavailable
	}
	info, err := buildinfo.Read(bytes.NewReader(tool))
	if err != nil || info.Path != "cmd/gofmt" || info.GoVersion != record.VersionEvidence.Identity || normalizeGoVersion(info.GoVersion) != record.ToolVersion {
		return nil, ErrFormatterMaterialUnavailable
	}
	if canonical, err := canonicaljson.Canonicalize(input.PlanJSON); err != nil || !bytes.Equal(canonical, input.PlanJSON) {
		return nil, ErrFormatterMaterialUnavailable
	}
	content, _ := formatterContent(input, recordBytes)
	closure, err := trustverify.ComputeContentClosureSHA256(content)
	if err != nil || closure != action.Action.ContentClosureSHA256 {
		return nil, ErrFormatterMaterialUnavailable
	}
	env := fixedEnvironment()
	envDigest, err := trustverify.ComputeEnvironmentPolicySHA256(env)
	if err != nil || envDigest != action.EnvironmentPolicySHA256 {
		return nil, ErrFormatterMaterialUnavailable
	}
	if opts, err := trustverify.ComputeToolOptionsSHA256(actionToolOptions(action)); err != nil || opts != action.Tool.OptionsSHA256 {
		return nil, ErrFormatterMaterialUnavailable
	}
	return &FormatterSelection{runtime: runtime, providerRuntime: runtime, toolRuntime: runtime, provider: provider, toolProvider: toolProvider, operation: cloneOperation(operation), action: cloneActionMaterial(action), tool: append([]byte(nil), tool...), input: append([]byte(nil), input.Bytes...), plan: append([]byte(nil), input.PlanJSON...), context: append([]byte(nil), input.ContextJSON...), record: append([]byte(nil), recordBytes...), path: input.Path, mode: input.Mode}, nil
}

func BindFormatterMaterial(ctx context.Context, runtime *trustverify.Runtime, provider, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput, selection *FormatterSelection) (*ExecutionMaterial, error) {
	if selection == nil || selection.sources != nil || selection.runtime != runtime || selection.provider != provider || selection.toolProvider != toolProvider || !reflect.DeepEqual(selection.operation, operation) || !reflect.DeepEqual(selection.action, action) || !reflect.DeepEqual(selection.input, input.Bytes) || !reflect.DeepEqual(selection.plan, input.PlanJSON) || !bytes.Equal(selection.context, input.ContextJSON) || selection.path != input.Path || selection.mode != input.Mode {
		return nil, ErrFormatterMaterialUnavailable
	}
	again, err := ResolveFormatterComposition(ctx, runtime, provider, toolProvider, operation, action, input)
	if err != nil || !reflect.DeepEqual(again.tool, selection.tool) || !reflect.DeepEqual(again.plan, selection.plan) || !reflect.DeepEqual(again.record, selection.record) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return &ExecutionMaterial{formatter: selection}, nil
}

func (m *ExecutionMaterial) stagedFormatter(ctx context.Context, runtime *trustverify.Runtime, request trustverify.ExecutionRequest) (trustverify.StagedMaterial, error) {
	if ctx == nil || ctx.Err() != nil || m == nil || m.formatter == nil || m.formatter.runtime != runtime || !m.formatter.provider.ValidFor(runtime, runtime.Binding()) || !m.formatter.toolProvider.ValidFor(runtime, runtime.Binding()) || request.VerifyRequestSHA256() != nil || !reflect.DeepEqual(m.formatter.action, actionMaterial(request)) {
		return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
	}
	s := m.formatter
	if s.sources != nil {
		if s.installed == nil || s.installed.TrustRuntime() != runtime {
			return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
		}
		if s.updateCalculation != nil {
			if s.calculation != nil {
				return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
			}
			if s.mergedCalculation != nil {
				if err := s.mergedCalculation.ValidateContext(ctx, s.installed, s.context, s.path, s.input); err != nil {
					return trustverify.StagedMaterial{}, err
				}
			} else if err := s.updateCalculation.ValidateCleanContext(ctx, s.installed, s.context, s.path, s.input); err != nil {
				return trustverify.StagedMaterial{}, err
			}
		} else if err := s.calculation.ValidateContext(ctx, s.installed, s.context, s.path, s.input); err != nil {
			return trustverify.StagedMaterial{}, err
		}
	}
	// The provider is reverified by RecheckExecution. The tool can belong to a
	// different signed source, so refresh it here for every Execute attempt.
	fresh, err := runtime.VerifySubject(ctx, s.toolProvider.Subject(), s.toolProvider.Evidence())
	if err != nil || fresh == nil || !reflect.DeepEqual(fresh.Subject(), s.toolProvider.Subject()) {
		return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
	}
	snapshot, err := runtime.VerifiedSnapshot(fresh)
	if err != nil || snapshot == nil {
		return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
	}
	record, recordOK := snapshot.Blob(formatterToolRecordPath)
	tool, toolOK := snapshot.Blob(formatterToolBinaryPath)
	if !recordOK || !toolOK || !bytes.Equal(record, s.record) || !bytes.Equal(tool, s.tool) {
		return trustverify.StagedMaterial{}, ErrFormatterMaterialUnavailable
	}
	input := FormatterInput{Path: s.path, Mode: s.mode, Bytes: s.input, PlanJSON: s.plan, ContextJSON: s.context}
	content, contentBytes := formatterContent(input, s.record)
	return trustverify.StagedMaterial{Operation: cloneOperation(s.operation), Request: cloneRequest(request), Content: content, ContentBytes: contentBytes, ToolBytes: append([]byte(nil), s.tool...), ToolOptions: actionToolOptions(s.action), Environment: fixedEnvironment()}, nil
}

func formatterContent(input FormatterInput, record []byte) ([]trustverify.ContentEntry, [][]byte) {
	type pair struct {
		entry trustverify.ContentEntry
		bytes []byte
	}
	pairs := []pair{{trustverify.ContentEntry{Root: "project", Path: input.Path, Mode: input.Mode, ContentSHA256: evidencecas.Digest(input.Bytes)}, append([]byte(nil), input.Bytes...)}, {trustverify.ContentEntry{Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: evidencecas.Digest(input.PlanJSON)}, append([]byte(nil), input.PlanJSON...)}, {trustverify.ContentEntry{Root: "project", Path: formatterToolRecordPath, Mode: "100644", ContentSHA256: evidencecas.Digest(record)}, append([]byte(nil), record...)}}
	if len(input.ContextJSON) > 0 {
		pairs = append(pairs, pair{trustverify.ContentEntry{Root: "project", Path: "formatter/context.json", Mode: "100644", ContentSHA256: evidencecas.Digest(input.ContextJSON)}, append([]byte(nil), input.ContextJSON...)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].entry.Root+"\x00"+pairs[i].entry.Path < pairs[j].entry.Root+"\x00"+pairs[j].entry.Path
	})
	entries, values := make([]trustverify.ContentEntry, len(pairs)), make([][]byte, len(pairs))
	for i := range pairs {
		entries[i], values[i] = pairs[i].entry, pairs[i].bytes
	}
	return entries, values
}

func mustBlob(s *trustverify.SourceSnapshot, path string) []byte {
	b, _ := s.Blob(path)
	return b
}

func formatterToolEntry(entries []trustverify.SourceEntry, digest string) bool {
	for _, entry := range entries {
		if entry.Path == formatterToolBinaryPath && entry.Kind == "file" && entry.Mode == "100755" && entry.ContentSHA256 == digest {
			return true
		}
	}
	return false
}

func parseFormatterToolRecord(raw []byte) (formatterToolRecord, error) {
	var record formatterToolRecord
	if len(raw) == 0 || len(raw) > 1<<20 {
		return record, ErrFormatterMaterialUnavailable
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return record, ErrFormatterMaterialUnavailable
	}
	if err := canonicaljson.DecodeStrict(raw, &record); err != nil {
		return record, ErrFormatterMaterialUnavailable
	}
	if record.APIVersion != "tplaiter.dev/formatter-tool/v1" || record.Adapter == "" || record.ToolID == "" || record.ToolVersion == "" || record.BinarySHA256 == "" || record.VersionEvidence.Kind == "" || record.VersionEvidence.Identity == "" || record.NativeEnvelope == "" {
		return formatterToolRecord{}, ErrFormatterMaterialUnavailable
	}
	return record, nil
}

func normalizeGoVersion(version string) string {
	return strings.TrimPrefix(version, "go")
}

func reservedFormatterInputPath(path string) bool {
	folded := strings.ToLower(path)
	return folded == "formatter" || strings.HasPrefix(folded, "formatter/") || folded == "native-tool" || folded == ".tplaiter-execution" || strings.HasPrefix(folded, ".tplaiter-execution/")
}

func actionToolOptions(a trustverify.ActionMaterial) []string {
	if len(a.Action.Argv) <= 1 {
		return []string{}
	}
	return append([]string(nil), a.Action.Argv[1:]...)
}

func cloneActionMaterial(a trustverify.ActionMaterial) trustverify.ActionMaterial {
	a.Action.Argv = append([]string(nil), a.Action.Argv...)
	return a
}

// ContextNewFormatterContext is closed action data. Its source admission comes
// only from the original same-runtime closure, never from these digest fields.
type ContextNewFormatterContext struct {
	APIVersion                    string `json:"apiVersion"`
	Role                          string `json:"role"`
	SourceRootLockSHA256          string `json:"sourceRootLockSHA256"`
	TargetRootLockSHA256          string `json:"targetRootLockSHA256"`
	ReplacementDeclarationsSHA256 string `json:"replacementDeclarationsSHA256"`
	DecisionsSHA256               string `json:"decisionsSHA256"`
	ObservedProjectSHA256         string `json:"observedProjectSHA256"`
	ObservedRegistrySHA256        string `json:"observedRegistrySHA256"`
	RendererAnswersSHA256         string `json:"rendererAnswersSHA256"`
	PredecessorCleanProofSHA256   string `json:"predecessorCleanProofSHA256,omitempty"`
	DependencyLockSHA256          string `json:"dependencyLockSHA256"`
	SourceGraphSHA256             string `json:"sourceGraphSHA256"`
	NativeContextSHA256           string `json:"nativeContextSHA256"`
}

func ParseContextNewFormatterContext(raw []byte) (ContextNewFormatterContext, error) {
	var c ContextNewFormatterContext
	if len(raw) == 0 || len(raw) > 1<<20 || canonicaljson.DecodeStrict(raw, &c) != nil {
		return c, ErrFormatterMaterialUnavailable
	}
	canonical, err := canonicaljson.Canonical(c)
	if err != nil || !bytes.Equal(raw, canonical) || c.APIVersion != "tplaiter.dev/managed-formatter-context/v2" || c.Role != "clean-target" || c.PredecessorCleanProofSHA256 != "" || c.SourceRootLockSHA256 != c.TargetRootLockSHA256 || c.ObservedProjectSHA256 != evidencecas.Digest(nil) {
		return ContextNewFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	for _, d := range []string{c.SourceRootLockSHA256, c.TargetRootLockSHA256, c.ReplacementDeclarationsSHA256, c.DecisionsSHA256, c.ObservedProjectSHA256, c.ObservedRegistrySHA256, c.RendererAnswersSHA256, c.DependencyLockSHA256, c.SourceGraphSHA256, c.NativeContextSHA256} {
		if !formatterDigest(d) {
			return ContextNewFormatterContext{}, ErrFormatterMaterialUnavailable
		}
	}
	emptyDecisions := []byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)
	emptyReplacement := []byte(`{"replacements":[],"version":1}`)
	if c.DecisionsSHA256 != evidencecas.Digest(emptyDecisions) || c.ReplacementDeclarationsSHA256 != evidencecas.Digest(emptyReplacement) {
		return ContextNewFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	return c, nil
}

// ResolveContextNewFormatterComposition is New-only. It preserves the legacy
// v1 entry and admits no retry selected by raw contract/version data.
func ResolveContextNewFormatterComposition(ctx context.Context, r *trustload.Runtime, calculation *ContextNewFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || calculation == nil || toolProvider == nil || operation.Scope != "new" || operation.ProjectID != r.ProjectContext().ProjectID || operation.PreimageSHA256 != evidencecas.Digest(nil) || len(operation.Actions) != 2 {
		return nil, ErrFormatterMaterialUnavailable
	}
	if err := calculation.ValidateContext(ctx, r, input.ContextJSON, input.Path, input.Bytes); err != nil {
		return nil, err
	}
	sources := calculation.sources
	if calculation.operation == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	c, err := ParseContextNewFormatterContext(input.ContextJSON)
	if err != nil {
		return nil, err
	}
	if c.RendererAnswersSHA256 != operation.AnswersSHA256 {
		return nil, ErrFormatterMaterialUnavailable
	}
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil || operation.ProfileBindingSHA256 != binding {
		return nil, ErrFormatterMaterialUnavailable
	}
	graph, err := calculation.operation.SourceGraph()
	if err != nil {
		return nil, err
	}
	graphDigest, err := bootstrap.DomainDigest("tplaiter.dev/managed-formatter-source-graph/v2", graph)
	if err != nil || c.SourceGraphSHA256 != graphDigest {
		return nil, ErrFormatterMaterialUnavailable
	}
	subjects, err := calculation.operation.OperationSubjects()
	if err != nil {
		return nil, err
	}
	if !toolProvider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	tool := toolProvider.Subject()
	subjects = append(subjects, trustverify.Provider{Origin: tool.Origin, TemplatePath: tool.TemplatePath, Commit: tool.Commit, TreeSHA256: tool.TreeSHA256, ContractSHA256: tool.ContractSHA256})
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	sort.Slice(subjects, func(i, j int) bool { return key(subjects[i]) < key(subjects[j]) })
	expected := []trustverify.Provider{}
	for _, subject := range subjects {
		if len(expected) > 0 && key(expected[len(expected)-1]) == key(subject) {
			if expected[len(expected)-1] != subject {
				return nil, ErrFormatterMaterialUnavailable
			}
			continue
		}
		expected = append(expected, subject)
	}
	if !reflect.DeepEqual(operation.Subjects, expected) {
		return nil, ErrFormatterMaterialUnavailable
	}
	root, err := calculation.operation.RootResolution()
	if err != nil {
		return nil, err
	}
	selection, err := resolveFormatterTool(ctx, r.TrustRuntime(), root, toolProvider, operation, action, input)
	if err != nil {
		return nil, err
	}
	selection.installed = r
	selection.calculation = calculation
	selection.sources = sources
	return selection, nil
}

func BindContextNewFormatterMaterial(ctx context.Context, r *trustload.Runtime, calculation *ContextNewFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput, selection *FormatterSelection) (*ExecutionMaterial, error) {
	if selection == nil || r == nil || selection.installed != r || selection.calculation != calculation || selection.runtime != r.TrustRuntime() || selection.toolProvider != toolProvider || !reflect.DeepEqual(selection.operation, operation) || !reflect.DeepEqual(selection.action, action) || !bytes.Equal(selection.input, input.Bytes) || !bytes.Equal(selection.plan, input.PlanJSON) || !bytes.Equal(selection.context, input.ContextJSON) || selection.path != input.Path || selection.mode != input.Mode {
		return nil, ErrFormatterMaterialUnavailable
	}
	again, err := ResolveContextNewFormatterComposition(ctx, r, calculation, toolProvider, operation, action, input)
	if err != nil || again.provider != selection.provider || !bytes.Equal(again.tool, selection.tool) || !bytes.Equal(again.record, selection.record) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return &ExecutionMaterial{formatter: selection}, nil
}

// ValidateRetainedFormatterContext selects only a closed data decoder. It
// authenticates neither a source closure nor a recorded effect or actor.
func ValidateRetainedFormatterContext(raw []byte, scope string) error {
	var header struct {
		APIVersion string `json:"apiVersion"`
	}
	if len(raw) == 0 || len(raw) > 1<<20 || json.Unmarshal(raw, &header) != nil {
		return ErrFormatterMaterialUnavailable
	}
	switch header.APIVersion {
	case "tplaiter.dev/managed-formatter-context/v1":
		_, err := ParseManagedFormatterContext(raw)
		return err
	case "tplaiter.dev/managed-formatter-context/v3":
		if scope != "update" {
			return ErrFormatterMaterialUnavailable
		}
		_, err := ParseContextUpdateFormatterContext(raw)
		return err
	case "tplaiter.dev/managed-formatter-context/v2":
		if scope != "new" {
			return ErrFormatterMaterialUnavailable
		}
		_, err := ParseContextNewFormatterContext(raw)
		return err
	default:
		return ErrFormatterMaterialUnavailable
	}
}

// ContextNewFormatterCalculation retains independently calculated render facts.
// Detached context JSON and operation labels cannot construct this carrier.
type ContextNewFormatterCalculation struct {
	owner                                      *trustload.Runtime
	sources                                    *contextauth.VerifiedSourceClosure
	operation                                  *contextauth.SourceClosureOperation
	self                                       *ContextNewFormatterCalculation
	root, dependencies, graph, native, answers string
	files                                      map[string][]byte
}

func PrepareContextNewFormatterCalculation(ctx context.Context, r *trustload.Runtime, sources *contextauth.VerifiedSourceClosure, render renderref.Input, renderer string) (*ContextNewFormatterCalculation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || sources == nil || !rendererToken.MatchString(renderer) {
		return nil, ErrFormatterMaterialUnavailable
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	sourceOperation, err := sources.BeginOperation(ctx, r)
	if err != nil {
		return nil, err
	}
	resolution, err := sourceOperation.RootResolution()
	if err != nil {
		return nil, err
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	manifestRaw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, err := contextwire.DecodeNativeContextContractV2(snapshot.ContractBytes(), manifestRaw); err != nil {
		return nil, err
	}
	src, err := SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		return nil, err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || tpl.AIConfig.Path != "" || ValidateBoundProjectBuildContent(snapshot, tpl) != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	if err := settings.ValidateFreshValues(tpl, render.Values); err != nil {
		return nil, err
	}
	render.Values = render.Values.Clone()
	result, err := renderref.RenderInScratch(ctx, src, render, r.ScratchRoot())
	if err != nil {
		return nil, err
	}
	subject, evidence := resolution.Subject(), resolution.Evidence()
	binding := r.TrustRuntime().Binding()
	root := provenance.RootTemplateLock{APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256}, Root: provenance.RootSubjectFromTrust(subject, bootstrap.PublisherEvidence{StatementCAS: evidence.StatementCAS, SignatureCAS: evidence.SignatureCAS, KeyFingerprint: evidence.KeyFingerprint}, evidence.CheckpointCAS, evidence.InclusionProofCAS), Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: renderer}}
	root.RootLockSHA256, err = provenance.ComputeRootLockSHA256(root)
	if err != nil {
		return nil, err
	}
	dependencies := provenance.TemplateLock{APIVersion: provenance.TemplateLockAPIVersion, Kind: provenance.DependencyExportLockKind, TrustProfile: binding, RootLockSHA256: root.RootLockSHA256, Dependencies: []provenance.DependencySubject{}}
	pins, err := sourceOperation.Pins()
	if err != nil {
		return nil, err
	}
	rootPin, err := sourceOperation.RootPin()
	if err != nil {
		return nil, err
	}
	for _, pin := range pins {
		if pin.Alias == rootPin.Alias {
			continue
		}
		resolved, err := sourceOperation.Resolution(pin.Alias)
		if err != nil {
			return nil, err
		}
		s, e := resolved.Subject(), resolved.Evidence()
		dependencies.Dependencies = append(dependencies.Dependencies, provenance.DependencySubject(provenance.RootSubjectFromTrust(s, bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)))
	}
	sort.Slice(dependencies.Dependencies, func(i, j int) bool {
		a, b := dependencies.Dependencies[i], dependencies.Dependencies[j]
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	dependencies.LockSHA256, err = provenance.ComputeTemplateLockSHA256(dependencies)
	if err != nil || provenance.ValidateLockPair(root, dependencies) != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	graph, err := sourceOperation.SourceGraph()
	if err != nil {
		return nil, err
	}
	catalogs, err := sourceOperation.Catalogs()
	if err != nil {
		return nil, err
	}
	catalogWires := []exports.Catalog{}
	for _, c := range catalogs {
		catalogWires = append(catalogWires, c.Catalog)
	}
	type image struct{ Path, Mode, ContentSHA256 string }
	type managedFile struct {
		Path, Mode, InputSHA256 string
		Markers                 []blockmarkers.Marker
	}
	images := []image{}
	managed := []managedFile{}
	names := []string{}
	folded := map[string]bool{}
	for name := range result.Files {
		key := strings.ToLower(name)
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, "\\") || folded[key] || key == ".tplaiter" || strings.HasPrefix(key, ".tplaiter/") || key == ".tplater" || strings.HasPrefix(key, ".tplater/") {
			return nil, ErrFormatterMaterialUnavailable
		}
		folded[key] = true
		names = append(names, name)
	}
	for key := range folded {
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if folded[parent] {
				return nil, ErrFormatterMaterialUnavailable
			}
		}
	}
	sort.Strings(names)
	mentions := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := result.Files[name]
		digest := evidencecas.Digest(data)
		images = append(images, image{name, "100644", digest})
		if !bytes.Contains(data, []byte("tplater:managed-")) {
			continue
		}
		mentions += bytes.Count(data, []byte("tplater:managed-"))
		if !strings.HasSuffix(name, ".go") || mentions > 8192 || len(managed) >= 4096 {
			return nil, ErrFormatterMaterialUnavailable
		}
		markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, name, data)
		if err != nil || len(markers) == 0 {
			return nil, ErrFormatterMaterialUnavailable
		}
		managed = append(managed, managedFile{name, "100644", digest, markers})
	}
	if len(managed) == 0 {
		return nil, ErrFormatterMaterialUnavailable
	}
	native, err := bootstrap.DomainDigest("tplaiter.dev/native-managed-new-context/v2", struct {
		Root         provenance.RootTemplateLock
		Dependencies provenance.TemplateLock
		Render       renderref.Input
		Values       settings.Values
		Graph        deps.SourceGraph
		Catalogs     []exports.Catalog
		Images       []image
		Managed      []managedFile
	}{root, dependencies, render, result.Resolved.Values, graph, catalogWires, images, managed})
	if err != nil {
		return nil, err
	}
	graphDigest, err := bootstrap.DomainDigest("tplaiter.dev/managed-formatter-source-graph/v2", graph)
	if err != nil {
		return nil, err
	}
	answers, err := canonicaljson.Canonical(result.Resolved.Values)
	if err != nil {
		return nil, err
	}
	p := &ContextNewFormatterCalculation{owner: r, sources: sources, operation: sourceOperation, root: root.RootLockSHA256, dependencies: dependencies.LockSHA256, graph: graphDigest, native: native, answers: evidencecas.Digest(answers), files: map[string][]byte{}}
	for _, file := range managed {
		p.files[file.Path] = bytes.Clone(result.Files[file.Path])
	}
	p.self = p
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ContextNewFormatterCalculation) check(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || p.self != p || r == nil || p.owner != r || p.sources == nil {
		return ErrFormatterMaterialUnavailable
	}
	if p.operation == nil {
		return ErrFormatterMaterialUnavailable
	}
	return p.operation.Check(ctx, r)
}

// RecheckFor establishes fresh signed source and CAS admission, not just carrier validity.
func (p *ContextNewFormatterCalculation) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if err := p.check(ctx, r); err != nil {
		return err
	}
	return p.operation.FinalRecheck(ctx, r)
}

func (p *ContextNewFormatterCalculation) ValidateContext(ctx context.Context, r *trustload.Runtime, raw []byte, name string, input []byte) error {
	if err := p.check(ctx, r); err != nil {
		return err
	}
	c, err := ParseContextNewFormatterContext(raw)
	if err != nil {
		return err
	}
	expected, ok := p.files[name]
	if !ok || !bytes.Equal(expected, input) || c.SourceRootLockSHA256 != p.root || c.TargetRootLockSHA256 != p.root || c.DependencyLockSHA256 != p.dependencies || c.SourceGraphSHA256 != p.graph || c.NativeContextSHA256 != p.native || c.RendererAnswersSHA256 != p.answers {
		return ErrFormatterMaterialUnavailable
	}
	return nil
}

func (p *ContextNewFormatterCalculation) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	if err := p.check(ctx, r); err != nil {
		return nil, err
	}
	return p.operation.RootResolution()
}

// ContextUpdateFormatterContext is a distinct closed native-v2 Update frame.
// Both dependency closures are bound, including the previous clean effect for
// a merged candidate. Parsing this data never grants execution or publication.
type ContextUpdateFormatterContext struct {
	APIVersion                    string `json:"apiVersion"`
	Role                          string `json:"role"`
	SourceRootLockSHA256          string `json:"sourceRootLockSHA256"`
	TargetRootLockSHA256          string `json:"targetRootLockSHA256"`
	SourceDependencyLockSHA256    string `json:"sourceDependencyLockSHA256"`
	TargetDependencyLockSHA256    string `json:"targetDependencyLockSHA256"`
	SourceGraphSHA256             string `json:"sourceGraphSHA256"`
	TargetGraphSHA256             string `json:"targetGraphSHA256"`
	SourceNativeContextSHA256     string `json:"sourceNativeContextSHA256"`
	TargetNativeContextSHA256     string `json:"targetNativeContextSHA256"`
	ReplacementDeclarationsSHA256 string `json:"replacementDeclarationsSHA256"`
	DecisionsSHA256               string `json:"decisionsSHA256"`
	ObservedProjectSHA256         string `json:"observedProjectSHA256"`
	ObservedRegistrySHA256        string `json:"observedRegistrySHA256"`
	RendererAnswersSHA256         string `json:"rendererAnswersSHA256"`
	PredecessorCleanProofSHA256   string `json:"predecessorCleanProofSHA256,omitempty"`
}

func ParseContextUpdateFormatterContext(raw []byte) (ContextUpdateFormatterContext, error) {
	var c ContextUpdateFormatterContext
	if len(raw) == 0 || len(raw) > 1<<20 || canonicaljson.DecodeStrict(raw, &c) != nil {
		return c, ErrFormatterMaterialUnavailable
	}
	encoded, err := canonicaljson.Canonical(c)
	if err != nil || !bytes.Equal(encoded, raw) || c.APIVersion != "tplaiter.dev/managed-formatter-context/v3" || (c.Role != "clean-target" && c.Role != "merged-candidate") {
		return ContextUpdateFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	for _, d := range []string{c.SourceRootLockSHA256, c.TargetRootLockSHA256, c.SourceDependencyLockSHA256, c.TargetDependencyLockSHA256, c.SourceGraphSHA256, c.TargetGraphSHA256, c.SourceNativeContextSHA256, c.TargetNativeContextSHA256, c.ReplacementDeclarationsSHA256, c.DecisionsSHA256, c.ObservedProjectSHA256, c.ObservedRegistrySHA256, c.RendererAnswersSHA256} {
		if !formatterDigest(d) {
			return ContextUpdateFormatterContext{}, ErrFormatterMaterialUnavailable
		}
	}
	if c.Role == "merged-candidate" && !formatterDigest(c.PredecessorCleanProofSHA256) || c.Role == "clean-target" && c.PredecessorCleanProofSHA256 != "" {
		return ContextUpdateFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	return c, nil
}

type recordedFormatterCalculation struct {
	owner                                      *trustload.Runtime
	sources                                    *contextauth.VerifiedSourceClosure
	self                                       *recordedFormatterCalculation
	root, dependencies, graph, native, answers string
	files                                      map[string][]byte
	template                                   *manifest.Template
	provider                                   *trustverify.VerifiedResolution
	subjects                                   []trustverify.Provider
}

// ContextUpdateFormatterCalculation is an opaque two-closure recorded
// calculation. It owns source facts independently of supplied context digests.
type ContextUpdateFormatterCalculation struct {
	owner                                       *trustload.Runtime
	self                                        *ContextUpdateFormatterCalculation
	source, target                              *recordedFormatterCalculation
	replacements, decisions, observed, registry string
}

func PrepareContextUpdateFormatterCalculation(ctx context.Context, r *trustload.Runtime, source, target *contextauth.VerifiedSourceClosure, sourceRender, targetRender renderref.Input, sourceRecorded, targetRecorded settings.Values, renderer, observed, registry string, decisionsRaw []byte) (*ContextUpdateFormatterCalculation, error) {
	if source == nil || target == nil || source == target {
		return nil, ErrFormatterMaterialUnavailable
	}
	if !formatterDigest(observed) || !formatterDigest(registry) {
		return nil, ErrFormatterMaterialUnavailable
	}
	decisions, err := managedblocks.ParseDecisions(decisionsRaw)
	if err != nil {
		return nil, err
	}
	encoded, err := canonicaljson.Canonical(decisions)
	if err != nil || !bytes.Equal(encoded, decisionsRaw) {
		return nil, ErrFormatterMaterialUnavailable
	}
	before, err := prepareRecordedFormatterCalculation(ctx, r, source, sourceRender, sourceRecorded, renderer)
	if err != nil {
		return nil, err
	}
	after, err := prepareRecordedFormatterCalculation(ctx, r, target, targetRender, targetRecorded, renderer)
	if err != nil {
		return nil, err
	}
	replacements := after.template.ManagedBlocks
	if replacements == nil {
		replacements = &manifest.ManagedBlocks{Version: 1, Replacements: []manifest.ManagedReplacement{}}
	}
	raw, err := canonicaljson.Canonical(replacements)
	if err != nil {
		return nil, err
	}
	p := &ContextUpdateFormatterCalculation{owner: r, source: before, target: after, replacements: evidencecas.Digest(raw), decisions: evidencecas.Digest(encoded), observed: observed, registry: registry}
	p.self = p
	if err := p.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ContextUpdateFormatterCalculation) RecheckFor(ctx context.Context, r *trustload.Runtime) error {
	if p == nil || p.self != p || ctx == nil || r == nil || p.owner != r || p.source == nil || p.target == nil {
		return ErrFormatterMaterialUnavailable
	}
	for _, c := range []*recordedFormatterCalculation{p.source, p.target} {
		if c.self != c || c.owner != r || c.sources == nil {
			return ErrFormatterMaterialUnavailable
		}
		if err := c.sources.RecheckFor(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (p *ContextUpdateFormatterCalculation) Context(ctx context.Context, r *trustload.Runtime) (ContextUpdateFormatterContext, error) {
	if err := p.RecheckFor(ctx, r); err != nil {
		return ContextUpdateFormatterContext{}, err
	}
	return p.contextFacts(), nil
}

func (p *ContextUpdateFormatterCalculation) contextFacts() ContextUpdateFormatterContext {
	return ContextUpdateFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v3", Role: "clean-target", SourceRootLockSHA256: p.source.root, TargetRootLockSHA256: p.target.root, SourceDependencyLockSHA256: p.source.dependencies, TargetDependencyLockSHA256: p.target.dependencies, SourceGraphSHA256: p.source.graph, TargetGraphSHA256: p.target.graph, SourceNativeContextSHA256: p.source.native, TargetNativeContextSHA256: p.target.native, ReplacementDeclarationsSHA256: p.replacements, DecisionsSHA256: p.decisions, ObservedProjectSHA256: p.observed, ObservedRegistrySHA256: p.registry, RendererAnswersSHA256: p.target.answers}
}

func (p *ContextUpdateFormatterCalculation) ValidateCleanContext(ctx context.Context, r *trustload.Runtime, raw []byte, name string, input []byte) error {
	expected, err := p.Context(ctx, r)
	if err != nil {
		return err
	}
	c, err := ParseContextUpdateFormatterContext(raw)
	if err != nil || c != expected {
		return ErrFormatterMaterialUnavailable
	}
	data, ok := p.target.files[name]
	if !ok || !bytes.Equal(data, input) {
		return ErrFormatterMaterialUnavailable
	}
	if !bytes.Contains(data, []byte("tplater:managed-")) && !bytes.Contains(p.source.files[name], []byte("tplater:managed-")) {
		return ErrFormatterMaterialUnavailable
	}
	return nil
}

func (p *ContextUpdateFormatterCalculation) ValidateCleanContextAndRoot(ctx context.Context, r *trustload.Runtime, raw []byte, name string, input []byte) (*trustverify.VerifiedResolution, error) {
	if err := p.ValidateCleanContext(ctx, r, raw, name, input); err != nil {
		return nil, err
	}
	provider := p.target.provider
	if provider == nil || !provider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return provider, nil
}

func prepareRecordedFormatterCalculation(ctx context.Context, r *trustload.Runtime, sources *contextauth.VerifiedSourceClosure, render renderref.Input, recorded settings.Values, renderer string) (*recordedFormatterCalculation, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || sources == nil || recorded == nil || !rendererToken.MatchString(renderer) {
		return nil, ErrFormatterMaterialUnavailable
	}
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	resolution, err := sources.RootResolution(ctx, r)
	if err != nil {
		return nil, err
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	manifestRaw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, err := contextwire.DecodeNativeContextContractV2(snapshot.ContractBytes(), manifestRaw); err != nil {
		return nil, err
	}
	src, err := SnapshotFS(r.TrustRuntime(), resolution)
	if err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil {
		return nil, err
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || tpl.AIConfig.Path != "" || ValidateBoundProjectBuildContent(snapshot, tpl) != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	render.Values = render.Values.Clone()
	recorded = recorded.Clone()
	result, err := renderref.RenderRecordedInScratch(ctx, src, render, r.ScratchRoot(), recorded)
	if err != nil {
		return nil, err
	}
	subject, evidence := resolution.Subject(), resolution.Evidence()
	binding := r.TrustRuntime().Binding()
	root := provenance.RootTemplateLock{APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256}, Root: provenance.RootSubjectFromTrust(subject, bootstrap.PublisherEvidence{StatementCAS: evidence.StatementCAS, SignatureCAS: evidence.SignatureCAS, KeyFingerprint: evidence.KeyFingerprint}, evidence.CheckpointCAS, evidence.InclusionProofCAS), Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: renderer}}
	root.RootLockSHA256, err = provenance.ComputeRootLockSHA256(root)
	if err != nil {
		return nil, err
	}
	dependencies := provenance.TemplateLock{APIVersion: provenance.TemplateLockAPIVersion, Kind: provenance.DependencyExportLockKind, TrustProfile: binding, RootLockSHA256: root.RootLockSHA256, Dependencies: []provenance.DependencySubject{}}
	pins, err := sources.Pins(ctx)
	if err != nil {
		return nil, err
	}
	rootPin, err := sources.RootPin(ctx)
	if err != nil {
		return nil, err
	}
	for _, pin := range pins {
		if pin.Alias == rootPin.Alias {
			continue
		}
		resolved, err := sources.Resolution(ctx, pin.Alias)
		if err != nil {
			return nil, err
		}
		s, e := resolved.Subject(), resolved.Evidence()
		dependencies.Dependencies = append(dependencies.Dependencies, provenance.DependencySubject(provenance.RootSubjectFromTrust(s, bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)))
	}
	sort.Slice(dependencies.Dependencies, func(i, j int) bool {
		a, b := dependencies.Dependencies[i], dependencies.Dependencies[j]
		return a.Origin+"\x00"+a.TemplatePath+"\x00"+a.Commit < b.Origin+"\x00"+b.TemplatePath+"\x00"+b.Commit
	})
	dependencies.LockSHA256, err = provenance.ComputeTemplateLockSHA256(dependencies)
	if err != nil || provenance.ValidateLockPair(root, dependencies) != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	graph, err := sources.SourceGraph(ctx)
	if err != nil {
		return nil, err
	}
	catalogs, err := sources.Catalogs(ctx)
	if err != nil {
		return nil, err
	}
	catalogWires := []exports.Catalog{}
	for _, c := range catalogs {
		catalogWires = append(catalogWires, c.Catalog)
	}
	type image struct{ Path, Mode, ContentSHA256 string }
	type managedFile struct {
		Path, Mode, InputSHA256 string
		Markers                 []blockmarkers.Marker
	}
	images := []image{}
	managed := []managedFile{}
	names := []string{}
	folded := map[string]bool{}
	for name := range result.Files {
		key := strings.ToLower(name)
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, "\\") || folded[key] || key == ".tplaiter" || strings.HasPrefix(key, ".tplaiter/") || key == ".tplater" || strings.HasPrefix(key, ".tplater/") {
			return nil, ErrFormatterMaterialUnavailable
		}
		folded[key] = true
		names = append(names, name)
	}
	for key := range folded {
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if folded[parent] {
				return nil, ErrFormatterMaterialUnavailable
			}
		}
	}
	sort.Strings(names)
	mentions := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := result.Files[name]
		digest := evidencecas.Digest(data)
		images = append(images, image{name, "100644", digest})
		if !bytes.Contains(data, []byte("tplater:managed-")) {
			continue
		}
		mentions += bytes.Count(data, []byte("tplater:managed-"))
		if !strings.HasSuffix(name, ".go") || mentions > 8192 || len(managed) >= 4096 {
			return nil, ErrFormatterMaterialUnavailable
		}
		markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, name, data)
		if err != nil || len(markers) == 0 {
			return nil, ErrFormatterMaterialUnavailable
		}
		managed = append(managed, managedFile{name, "100644", digest, markers})
	}
	native, err := bootstrap.DomainDigest("tplaiter.dev/native-recorded-context/v2", struct {
		Root           provenance.RootTemplateLock
		Dependencies   provenance.TemplateLock
		Render         renderref.Input
		RecordedValues settings.Values
		Values         settings.Values
		Graph          deps.SourceGraph
		Catalogs       []exports.Catalog
		Images         []image
	}{root, dependencies, render, recorded, result.Resolved.Values, graph, catalogWires, images})
	if err != nil {
		return nil, err
	}
	graphDigest, err := bootstrap.DomainDigest("tplaiter.dev/managed-formatter-source-graph/v2", graph)
	if err != nil {
		return nil, err
	}
	answers, err := canonicaljson.Canonical(result.Resolved.Values)
	if err != nil {
		return nil, err
	}
	subjects, err := sources.OperationSubjects(ctx, r)
	if err != nil {
		return nil, err
	}
	p := &recordedFormatterCalculation{owner: r, sources: sources, provider: resolution, subjects: append([]trustverify.Provider(nil), subjects...), root: root.RootLockSHA256, dependencies: dependencies.LockSHA256, graph: graphDigest, native: native, answers: evidencecas.Digest(answers), files: map[string][]byte{}, template: tpl}
	for name, raw := range result.Files {
		p.files[name] = bytes.Clone(raw)
	}
	p.self = p
	if err := sources.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ContextUpdateFormatterCalculation) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	if err := p.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	if p.target.provider == nil || !p.target.provider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return p.target.provider, nil
}

func (p *ContextUpdateFormatterCalculation) OperationSubjects(ctx context.Context, r *trustload.Runtime) ([]trustverify.Provider, error) {
	if err := p.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return p.operationSubjectFacts()
}

func (p *ContextUpdateFormatterCalculation) operationSubjectFacts() ([]trustverify.Provider, error) {
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	subjects := map[string]trustverify.Provider{}
	for _, c := range []*recordedFormatterCalculation{p.source, p.target} {
		providers := c.subjects
		for _, provider := range providers {
			k := key(provider)
			if old, ok := subjects[k]; ok && old != provider {
				return nil, ErrFormatterMaterialUnavailable
			}
			subjects[k] = provider
		}
	}
	out := []trustverify.Provider{}
	for _, provider := range subjects {
		out = append(out, provider)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out, nil
}

func ResolveContextUpdateFormatterComposition(ctx context.Context, r *trustload.Runtime, calculation *ContextUpdateFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	return resolveContextUpdateFormatter(ctx, r, calculation, nil, toolProvider, operation, action, input)
}

func ResolveContextUpdateMergedFormatterComposition(ctx context.Context, r *trustload.Runtime, calculation *ContextUpdateMergedFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	if calculation == nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	return resolveContextUpdateFormatter(ctx, r, calculation.clean, calculation, toolProvider, operation, action, input)
}

func resolveContextUpdateFormatter(ctx context.Context, r *trustload.Runtime, calculation *ContextUpdateFormatterCalculation, merged *ContextUpdateMergedFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput) (*FormatterSelection, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || calculation == nil || toolProvider == nil || operation.Scope != "update" || operation.ProjectID != r.ProjectContext().ProjectID || len(operation.Actions) != 2 {
		return nil, ErrFormatterMaterialUnavailable
	}
	if merged != nil {
		if merged.clean != calculation {
			return nil, ErrFormatterMaterialUnavailable
		}
		if err := merged.ValidateContext(ctx, r, input.ContextJSON, input.Path, input.Bytes); err != nil {
			return nil, err
		}
	} else if err := calculation.ValidateCleanContext(ctx, r, input.ContextJSON, input.Path, input.Bytes); err != nil {
		return nil, err
	}
	c := calculation.contextFacts()
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil || operation.ProfileBindingSHA256 != binding || operation.PreimageSHA256 != c.ObservedProjectSHA256 || operation.AnswersSHA256 != c.RendererAnswersSHA256 || !toolProvider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	subjects, err := calculation.operationSubjectFacts()
	if err != nil {
		return nil, err
	}
	tool := toolProvider.Subject()
	subjects = append(subjects, trustverify.Provider{Origin: tool.Origin, TemplatePath: tool.TemplatePath, Commit: tool.Commit, TreeSHA256: tool.TreeSHA256, ContractSHA256: tool.ContractSHA256})
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	sort.Slice(subjects, func(i, j int) bool { return key(subjects[i]) < key(subjects[j]) })
	expected := []trustverify.Provider{}
	for _, subject := range subjects {
		if len(expected) > 0 && key(expected[len(expected)-1]) == key(subject) {
			if expected[len(expected)-1] != subject {
				return nil, ErrFormatterMaterialUnavailable
			}
			continue
		}
		expected = append(expected, subject)
	}
	if !reflect.DeepEqual(operation.Subjects, expected) {
		return nil, ErrFormatterMaterialUnavailable
	}
	provider := calculation.target.provider
	if provider == nil || !provider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	selection, err := resolveFormatterTool(ctx, r.TrustRuntime(), provider, toolProvider, operation, action, input)
	if err != nil {
		return nil, err
	}
	selection.installed = r
	selection.sources = calculation.target.sources
	selection.updateCalculation = calculation
	selection.mergedCalculation = merged
	if err := calculation.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	return selection, nil
}

func BindContextUpdateFormatterMaterial(ctx context.Context, r *trustload.Runtime, calculation *ContextUpdateFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput, selection *FormatterSelection) (*ExecutionMaterial, error) {
	if selection == nil || r == nil || selection.installed != r || selection.updateCalculation != calculation || selection.calculation != nil || selection.runtime != r.TrustRuntime() || selection.toolProvider != toolProvider || !reflect.DeepEqual(selection.operation, operation) || !reflect.DeepEqual(selection.action, action) || !bytes.Equal(selection.input, input.Bytes) || !bytes.Equal(selection.plan, input.PlanJSON) || !bytes.Equal(selection.context, input.ContextJSON) || selection.path != input.Path || selection.mode != input.Mode {
		return nil, ErrFormatterMaterialUnavailable
	}
	again, err := ResolveContextUpdateFormatterComposition(ctx, r, calculation, toolProvider, operation, action, input)
	if err != nil || again.provider != selection.provider || !bytes.Equal(again.tool, selection.tool) || !bytes.Equal(again.record, selection.record) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return &ExecutionMaterial{formatter: selection}, nil
}

// ContextUpdateMergedFormatterCalculation owns one source-bound candidate and
// predecessor data. It never authenticates an effect or grants publication;
// the effect owner verifies the actual clean pair before construction.
type ContextUpdateMergedFormatterCalculation struct {
	self        *ContextUpdateMergedFormatterCalculation
	clean       *ContextUpdateFormatterCalculation
	name        string
	input       []byte
	predecessor string
}

func PrepareContextUpdateMergedFormatterCalculation(ctx context.Context, r *trustload.Runtime, clean *ContextUpdateFormatterCalculation, name string, input []byte, predecessor string) (*ContextUpdateMergedFormatterCalculation, error) {
	if err := clean.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	if !formatterDigest(predecessor) || len(input) == 0 || len(input) > 16<<20 || !strings.HasSuffix(name, ".go") {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, ok := clean.target.files[name]; !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	if !bytes.Contains(clean.target.files[name], []byte("tplater:managed-")) && !bytes.Contains(clean.source.files[name], []byte("tplater:managed-")) {
		return nil, ErrFormatterMaterialUnavailable
	}
	if _, err := blockmarkers.Validate(blockmarkers.LanguageGo, name, input); err != nil {
		return nil, err
	}
	p := &ContextUpdateMergedFormatterCalculation{clean: clean, name: name, input: bytes.Clone(input), predecessor: predecessor}
	p.self = p
	return p, nil
}

func (p *ContextUpdateMergedFormatterCalculation) Context(ctx context.Context, r *trustload.Runtime) (ContextUpdateFormatterContext, error) {
	if p == nil || p.self != p || p.clean == nil {
		return ContextUpdateFormatterContext{}, ErrFormatterMaterialUnavailable
	}
	c, err := p.clean.Context(ctx, r)
	if err != nil {
		return c, err
	}
	c.Role = "merged-candidate"
	c.PredecessorCleanProofSHA256 = p.predecessor
	return c, nil
}

func (p *ContextUpdateMergedFormatterCalculation) ValidateContext(ctx context.Context, r *trustload.Runtime, raw []byte, name string, input []byte) error {
	expected, err := p.Context(ctx, r)
	if err != nil {
		return err
	}
	c, err := ParseContextUpdateFormatterContext(raw)
	if err != nil || c != expected || name != p.name || !bytes.Equal(input, p.input) {
		return ErrFormatterMaterialUnavailable
	}
	return nil
}

func (p *ContextUpdateMergedFormatterCalculation) ValidateContextAndRoot(ctx context.Context, r *trustload.Runtime, clean *ContextUpdateFormatterCalculation, raw []byte, name string, input []byte) (*trustverify.VerifiedResolution, error) {
	if p == nil || p.clean != clean {
		return nil, ErrFormatterMaterialUnavailable
	}
	if err := p.ValidateContext(ctx, r, raw, name, input); err != nil {
		return nil, err
	}
	provider := clean.target.provider
	if provider == nil || !provider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return provider, nil
}

func (p *ContextUpdateMergedFormatterCalculation) RootResolution(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	if _, err := p.Context(ctx, r); err != nil {
		return nil, err
	}
	return p.clean.RootResolution(ctx, r)
}

func BindContextUpdateMergedFormatterMaterial(ctx context.Context, r *trustload.Runtime, calculation *ContextUpdateMergedFormatterCalculation, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput, selection *FormatterSelection) (*ExecutionMaterial, error) {
	if calculation == nil || selection == nil || r == nil || selection.mergedCalculation != calculation || selection.updateCalculation != calculation.clean || selection.installed != r || selection.calculation != nil || selection.runtime != r.TrustRuntime() || selection.toolProvider != toolProvider || !reflect.DeepEqual(selection.operation, operation) || !reflect.DeepEqual(selection.action, action) || !bytes.Equal(selection.input, input.Bytes) || !bytes.Equal(selection.plan, input.PlanJSON) || !bytes.Equal(selection.context, input.ContextJSON) || selection.path != input.Path || selection.mode != input.Mode {
		return nil, ErrFormatterMaterialUnavailable
	}
	again, err := ResolveContextUpdateMergedFormatterComposition(ctx, r, calculation, toolProvider, operation, action, input)
	if err != nil || again.provider != selection.provider || !bytes.Equal(again.tool, selection.tool) || !bytes.Equal(again.record, selection.record) {
		return nil, ErrFormatterMaterialUnavailable
	}
	return &ExecutionMaterial{formatter: selection}, nil
}
