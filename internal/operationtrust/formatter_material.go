package operationtrust

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var ErrFormatterMaterialUnavailable = errors.New("TRUST_FORMATTER_MATERIAL_UNAVAILABLE")

type FormatterSelection struct {
	runtime, providerRuntime, toolRuntime *trustverify.Runtime
	provider, toolProvider                *trustverify.VerifiedResolution
	operation                             trustverify.OperationInputs
	action                                trustverify.ActionMaterial
	tool, input, plan, record             []byte
	path, mode                            string
}

// FormatterInput carries sealed data only. It cannot select a binary, a
// runner, a source resolution, or a filesystem location outside the fixed
// logical formatter projection.
type FormatterInput struct {
	Path, Mode string
	Bytes      []byte
	PlanJSON   []byte
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
	if _, err := requireNativeContract(ps.ContractBytes(), mustBlob(ps, "template.manifest.yaml")); err != nil {
		return nil, ErrFormatterMaterialUnavailable
	}
	recordBytes, ok := ts.Blob(formatterToolRecordPath)
	if !ok {
		return nil, ErrFormatterMaterialUnavailable
	}
	record, err := parseFormatterToolRecord(recordBytes)
	if err != nil || record.Adapter != "gofmt-stdin-v1" || record.ToolID != "gofmt" || record.ToolVersion != action.Tool.Version || record.BinarySHA256 != action.Tool.BinarySHA256 || record.NativeEnvelope != "darwin-arm64-dyld-libsystem-libresolv-v1" {
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
	return &FormatterSelection{runtime: runtime, providerRuntime: runtime, toolRuntime: runtime, provider: provider, toolProvider: toolProvider, operation: cloneOperation(operation), action: cloneActionMaterial(action), tool: append([]byte(nil), tool...), input: append([]byte(nil), input.Bytes...), plan: append([]byte(nil), input.PlanJSON...), record: append([]byte(nil), recordBytes...), path: input.Path, mode: input.Mode}, nil
}

func BindFormatterMaterial(ctx context.Context, runtime *trustverify.Runtime, provider, toolProvider *trustverify.VerifiedResolution, operation trustverify.OperationInputs, action trustverify.ActionMaterial, input FormatterInput, selection *FormatterSelection) (*ExecutionMaterial, error) {
	if selection == nil || selection.runtime != runtime || selection.provider != provider || selection.toolProvider != toolProvider || !reflect.DeepEqual(selection.operation, operation) || !reflect.DeepEqual(selection.action, action) || !reflect.DeepEqual(selection.input, input.Bytes) || !reflect.DeepEqual(selection.plan, input.PlanJSON) || selection.path != input.Path || selection.mode != input.Mode {
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
	input := FormatterInput{Path: s.path, Mode: s.mode, Bytes: s.input, PlanJSON: s.plan}
	content, contentBytes := formatterContent(input, s.record)
	return trustverify.StagedMaterial{Operation: cloneOperation(s.operation), Request: cloneRequest(request), Content: content, ContentBytes: contentBytes, ToolBytes: append([]byte(nil), s.tool...), ToolOptions: actionToolOptions(s.action), Environment: fixedEnvironment()}, nil
}

func formatterContent(input FormatterInput, record []byte) ([]trustverify.ContentEntry, [][]byte) {
	type pair struct {
		entry trustverify.ContentEntry
		bytes []byte
	}
	pairs := []pair{{trustverify.ContentEntry{Root: "project", Path: input.Path, Mode: input.Mode, ContentSHA256: evidencecas.Digest(input.Bytes)}, append([]byte(nil), input.Bytes...)}, {trustverify.ContentEntry{Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: evidencecas.Digest(input.PlanJSON)}, append([]byte(nil), input.PlanJSON...)}, {trustverify.ContentEntry{Root: "project", Path: formatterToolRecordPath, Mode: "100644", ContentSHA256: evidencecas.Digest(record)}, append([]byte(nil), record...)}}
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
