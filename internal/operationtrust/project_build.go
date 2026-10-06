package operationtrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

var ErrProjectBuild = errors.New("TRUST_PROJECT_BUILD_UNAVAILABLE")

func ProjectBuildArguments() []string {
	return []string{"go", "build", "-mod=readonly", "-buildvcs=false", "./..."}
}

const ProjectBuildActionPath = "actions/run/build.json"

type ProjectBuildAction struct {
	APIVersion           string                `json:"apiVersion"`
	Adapter              string                `json:"adapter"`
	CommandName          string                `json:"commandName"`
	Argv                 []string              `json:"argv"`
	TimeoutMillis        int64                 `json:"timeoutMillis"`
	ToolchainIndexSHA256 string                `json:"toolchainIndexSHA256"`
	ModuleIndexSHA256    string                `json:"moduleIndexSHA256,omitempty"`
	GenBuild             bool                  `json:"genBuild,omitempty"`
	Selector             string                `json:"selector,omitempty"`
	Variants             []ProjectBuildVariant `json:"variants,omitempty"`
}
type ProjectBuildVariant struct {
	ID                string `json:"id"`
	Workflow          bool   `json:"workflow"`
	Policy            string `json:"policy"`
	GoModSHA256       string `json:"goModSHA256,omitempty"`
	GoSumSHA256       string `json:"goSumSHA256,omitempty"`
	ModuleIndexSHA256 string `json:"moduleIndexSHA256,omitempty"`
}

const projectBuildSelectionPath = "actions/run/build.selection.json"

type projectBuildVariantBinding struct {
	APIVersion     string              `json:"apiVersion"`
	ActionSHA256   string              `json:"actionSHA256"`
	MarkerSHA256   string              `json:"markerSHA256"`
	RootLockSHA256 string              `json:"rootLockSHA256"`
	Variant        ProjectBuildVariant `json:"variant"`
}
type ProjectBuildSelection struct {
	owner      *trustload.Runtime
	source     *trustverify.VerifiedResolution
	operation  trustverify.OperationInputs
	request    trustverify.ExecutionRequest
	entries    []trustverify.ContentEntry
	data       [][]byte
	action     []byte
	toolchain  *trustload.GoToolchain
	modules    *trustload.GoModules
	variant    *projectBuildVariantBinding
	variantRaw []byte
}

func ProjectBuildEnvironment() trustverify.EnvironmentPolicy {
	// @stage is an adapter-owned logical location, replaced only by the runner.
	vars := map[string]string{"LANG": "C", "CGO_ENABLED": "0", "GOENV": "off", "GOAUTH": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off", "GOVCS": "*:off", "GOTELEMETRY": "off", "GOROOT": "@stage/toolchain", "HOME": "@stage/home", "GOCACHE": "@stage/cache", "GOPATH": "@stage/gopath", "GOMODCACHE": "@stage/modules", "GOTMPDIR": "@stage/tmp", "TMPDIR": "@stage/tmp"}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	e := trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{}, Capabilities: []string{}}
	for _, k := range keys {
		e.Variables = append(e.Variables, trustverify.EnvironmentVariable{Name: k, Value: vars[k]})
	}
	return e
}
func PrepareProjectBuild(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, name string, values settings.Values) (*ProjectBuildSelection, error) {
	return prepareProjectBuild(ctx, owner, source, name, values, nil, "", "")
}

// PrepareProjectedProjectBuild binds a generator owner's authenticated projected
// inputs to a gen-scoped approval. Input data cannot grant a write capability;
// the concrete generator plan/transaction must independently authorize writes.
func PrepareProjectedProjectBuild(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, values settings.Values, images map[string][]byte, preimage, planDigest string) (*ProjectBuildSelection, error) {
	if images == nil || len(preimage) != 71 || len(planDigest) != 71 {
		return nil, ErrProjectBuild
	}
	return prepareProjectBuild(ctx, owner, source, "build", values, images, preimage, planDigest)
}
func prepareProjectBuild(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, name string, values settings.Values, images map[string][]byte, preimageOverride, planDigest string) (*ProjectBuildSelection, error) {
	if ctx == nil || owner == nil || owner.TrustRuntime() == nil || source == nil || name != "build" {
		return nil, fmt.Errorf("%w: runtime or selection", ErrProjectBuild)
	}
	stable := owner.TrustRuntime()
	snapshot, err := stable.VerifiedSnapshot(source)
	if err != nil {
		return nil, err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, ErrProjectBuild
	}
	if _, err = requireNativeContract(snapshot.ContractBytes(), raw); err != nil {
		return nil, err
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return nil, err
	}
	command, ok := tpl.Commands[name]
	if !ok || command.Run != strings.Join(ProjectBuildArguments(), " ") {
		return nil, fmt.Errorf("%w: manifest build declaration", ErrProjectBuild)
	}
	if command.When != "" {
		cond, err := manifest.ParseCondition(command.When)
		if err != nil {
			return nil, fmt.Errorf("%w: condition", ErrProjectBuild)
		}
		on, e := settings.Eval(cond, values)
		if e != nil || !on {
			return nil, ErrProjectBuild
		}
	}
	actionRaw, ok := snapshot.Blob(ProjectBuildActionPath)
	if !ok {
		return nil, ErrProjectBuild
	}
	var a ProjectBuildAction
	if decodeProjectBuildAction(actionRaw, &a) != nil || !validProjectBuildVersion(a) || a.CommandName != name || !reflect.DeepEqual(a.Argv, ProjectBuildArguments()) || a.TimeoutMillis < 1 || a.TimeoutMillis > 120000 {
		return nil, ErrProjectBuild
	}
	chain, err := owner.ResolveGoToolchain(ctx, source)
	if err != nil {
		return nil, err
	}
	if evidencecas.Digest(chain.IndexBytes()) != a.ToolchainIndexSHA256 {
		return nil, fmt.Errorf("%w: index binding", ErrProjectBuild)
	}
	var variant *projectBuildVariantBinding
	if a.APIVersion == "tplaiter.dev/project-build-action/v3" {
		trusted, marker, rootLock, e := projectBuildAnswers(ctx, owner, source, tpl)
		if e != nil || !reflect.DeepEqual(values, trusted) {
			return nil, ErrProjectBuild
		}
		values = trusted
		workflow, ok := trusted["workflow"].(bool)
		if !ok {
			return nil, ErrProjectBuild
		}
		v := a.Variants[0]
		if workflow {
			v = a.Variants[1]
		}
		variant = &projectBuildVariantBinding{APIVersion: "tplaiter.dev/project-build-selection/v1", ActionSHA256: evidencecas.Digest(actionRaw), MarkerSHA256: marker, RootLockSHA256: rootLock, Variant: v}
	}
	var entries []trustverify.ContentEntry
	var data [][]byte
	if images == nil {
		entries, data, err = captureProjectBuild(ctx, owner.ProjectContext().RootPath)
	} else {
		if (a.APIVersion != "tplaiter.dev/project-build-action/v2" && a.APIVersion != "tplaiter.dev/project-build-action/v3") || !a.GenBuild {
			return nil, ErrProjectBuild
		}
		entries, data, err = projectedBuildInputs(images)
	}

	if err != nil {
		return nil, fmt.Errorf("project input capture: %w", err)
	}
	var mod, sum []byte
	for i, f := range entries {
		if f.Path == "go.mod" {
			mod = data[i]
		}
		if f.Path == "go.sum" {
			sum = data[i]
		}
		if strings.Contains(string(data[i]), "//go:embed") || strings.Contains(string(data[i]), `import "C"`) {
			return nil, ErrProjectBuild
		}
	}
	parsed, err := modfile.Parse("go.mod", mod, nil)
	if err != nil || parsed.Module == nil || len(parsed.Replace) != 0 || len(parsed.Exclude) != 0 || parsed.Toolchain != nil {
		return nil, fmt.Errorf("%w: dependency-free module required", ErrProjectBuild)
	}
	var modules *trustload.GoModules
	moduleIndex := a.ModuleIndexSHA256
	if variant != nil {
		if err := checkVariantMarker(entries, data, variant.MarkerSHA256, variant.RootLockSHA256); err != nil {
			return nil, err
		}
		moduleIndex = variant.Variant.ModuleIndexSHA256
		if variant.Variant.Policy == "zero-external-modules" && (len(parsed.Require) != 0 || trustload.GoModuleProjectDigest(mod) != variant.Variant.GoModSHA256 || evidencecas.Digest(sum) != variant.Variant.GoSumSHA256) {
			return nil, ErrProjectBuild
		}
	}
	if a.APIVersion == "tplaiter.dev/project-build-action/v2" || (variant != nil && variant.Variant.Policy == "module-closure") {
		modules, err = owner.ResolveGoModules(ctx, source, mod, sum)
		if err != nil {
			return nil, err
		}
		if evidencecas.Digest(modules.IndexBytes()) != moduleIndex {
			return nil, ErrProjectBuild
		}
		for _, req := range parsed.Require {
			if !modules.Includes(req.Mod.Path, req.Mod.Version) {
				return nil, ErrProjectBuild
			}
		}
	} else if len(parsed.Require) != 0 {
		return nil, ErrProjectBuild
	}
	preimage, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		return nil, err
	}
	for _, v := range []struct {
		path  string
		bytes []byte
	}{{ProjectBuildActionPath, actionRaw}, {trustload.ToolchainIndexPath, chain.IndexBytes()}} {
		entries = append(entries, trustverify.ContentEntry{Root: "provider", Path: v.path, Mode: "100644", ContentSHA256: evidencecas.Digest(v.bytes)})
		data = append(data, append([]byte(nil), v.bytes...))
	}
	if modules != nil {
		b := modules.IndexBytes()
		entries = append(entries, trustverify.ContentEntry{Root: "provider", Path: trustload.GoModuleIndexPath, Mode: "100644", ContentSHA256: evidencecas.Digest(b)})
		data = append(data, b)
	}
	var variantRaw []byte
	if variant != nil {
		variantRaw, err = canonicaljson.Canonical(variant)
		if err != nil {
			return nil, err
		}
		entries = append(entries, trustverify.ContentEntry{Root: "provider", Path: projectBuildSelectionPath, Mode: "100644", ContentSHA256: evidencecas.Digest(variantRaw)})
		data = append(data, variantRaw)
	}
	// Content closure ordering is canonical across project and provider roots.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].Root+"\x00"+entries[j].Path < entries[j-1].Root+"\x00"+entries[j-1].Path; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
			data[j], data[j-1] = data[j-1], data[j]
		}
	}
	closure, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		return nil, err
	}
	bd, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, stable.Binding())
	if err != nil {
		return nil, err
	}
	var answers any = values
	scope, phase := "run", "standalone"
	if images != nil {
		scope, phase = "gen", "after"
		preimage = preimageOverride
		answers = struct {
			Values     settings.Values `json:"values"`
			PlanSHA256 string          `json:"planSHA256"`
		}{values, planDigest}
	}
	answerRaw, err := canonicaljson.Canonical(answers)
	if err != nil {
		return nil, err
	}
	envHash, _ := trustverify.ComputeEnvironmentPolicySHA256(ProjectBuildEnvironment())
	options, _ := trustverify.ComputeToolOptionsSHA256(a.Argv[1:])
	p := provider(source.Subject())
	act := trustverify.ActionMaterial{Provider: p, Action: trustverify.Action{ID: "build", Kind: "command", Phase: phase, Argv: append([]string(nil), a.Argv...), ContentClosureSHA256: closure}, Tool: trustverify.Tool{ID: "go", Version: chain.Version(), BinarySHA256: evidencecas.Digest(chain.Driver()), OptionsSHA256: options}, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: envHash, TimeoutMillis: a.TimeoutMillis, Migration: trustverify.Migration{Kind: "none"}}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: owner.ProjectContext().ProjectID, Scope: scope, PreimageSHA256: preimage, AnswersSHA256: evidencecas.Digest(answerRaw), Subjects: []trustverify.Provider{p}, Actions: []trustverify.ActionMaterial{act}}
	od, err := trustverify.ComputeOperationInputsSHA256(op)
	if err != nil {
		return nil, err
	}
	req := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: od, ProjectID: op.ProjectID, Scope: scope, Provider: p, Action: act.Action, Tool: act.Tool, WorkingDirectoryScope: act.WorkingDirectoryScope, EnvironmentPolicySHA256: act.EnvironmentPolicySHA256, TimeoutMillis: act.TimeoutMillis, Migration: act.Migration}
	req.RequestSHA256, err = req.ComputeRequestSHA256()
	if err != nil {
		return nil, err
	}
	return &ProjectBuildSelection{owner: owner, source: source, operation: op, request: req, entries: entries, data: data, action: actionRaw, toolchain: chain, modules: modules, variant: variant, variantRaw: variantRaw}, nil
}
func (s *ProjectBuildSelection) Operation() trustverify.OperationInputs {
	if s == nil {
		return trustverify.OperationInputs{}
	}
	return cloneOperation(s.operation)
}
func (s *ProjectBuildSelection) Request() trustverify.ExecutionRequest {
	if s == nil {
		return trustverify.ExecutionRequest{}
	}
	return cloneRequest(s.request)
}
func (s *ProjectBuildSelection) Resolution() *trustverify.VerifiedResolution {
	if s == nil {
		return nil
	}
	return s.source
}
func BindProjectBuildMaterial(ctx context.Context, owner *trustload.Runtime, s *ProjectBuildSelection) (*ExecutionMaterial, error) {
	if s == nil || s.owner != owner || owner.TrustRuntime() == nil {
		return nil, ErrProjectBuild
	}
	if err := s.recheck(ctx); err != nil {
		return nil, err
	}
	return &ExecutionMaterial{projectBuild: s}, nil
}
func (s *ProjectBuildSelection) recheck(ctx context.Context) error {
	if s == nil || s.owner.TrustRuntime() == nil {
		return ErrProjectBuild
	}
	if err := s.toolchain.Recheck(ctx); err != nil {
		return err
	}
	fresh, err := s.owner.TrustRuntime().VerifySubject(ctx, s.source.Subject(), s.source.Evidence())
	if err != nil {
		return err
	}
	snap, err := s.owner.TrustRuntime().VerifiedSnapshot(fresh)
	if err != nil {
		return err
	}
	a, ok := snap.Blob(ProjectBuildActionPath)
	if !ok || !bytes.Equal(a, s.action) {
		return ErrProjectBuild
	}
	entries, data, err := captureProjectBuild(ctx, s.owner.ProjectContext().RootPath)
	if err != nil {
		return err
	}
	if s.variant != nil {
		if err := s.owner.TrustRuntime().CheckProjectIdentity(ctx, s.owner.ProjectContext().RootPath, s.operation.ProjectID); err != nil {
			return err
		}
		if err := checkVariantMarker(entries, data, s.variant.MarkerSHA256, s.variant.RootLockSHA256); err != nil {
			return err
		}
	}
	providerEntries := 2
	if s.variant != nil {
		providerEntries++
	}
	if s.modules != nil {
		providerEntries++
	}
	if len(entries)+providerEntries != len(s.entries) {
		return ErrProjectBuild
	}
	for i := range entries {
		if entries[i] != s.entries[i] || !bytes.Equal(data[i], s.data[i]) {
			return ErrProjectBuild
		}
	}
	if s.modules != nil {
		var mod, sum []byte
		for i, f := range entries {
			if f.Path == "go.mod" {
				mod = data[i]
			}
			if f.Path == "go.sum" {
				sum = data[i]
			}
		}
		if err := s.modules.Recheck(ctx, mod, sum); err != nil {
			return err
		}
	}
	return nil
}
func (m *ExecutionMaterial) ProjectBuildFor(ctx context.Context, owner *trustload.Runtime, request trustverify.ExecutionRequest) (trustverify.StagedMaterial, *trustload.GoToolchain, error) {
	if ctx == nil || owner == nil || m == nil || m.projectBuild == nil || m.projectBuild.owner != owner || !reflect.DeepEqual(request, m.projectBuild.request) {
		return trustverify.StagedMaterial{}, nil, ErrProjectBuild
	}
	s := m.projectBuild
	if err := s.recheck(ctx); err != nil {
		return trustverify.StagedMaterial{}, nil, err
	}
	data := make([][]byte, len(s.data))
	for i := range data {
		data[i] = append([]byte(nil), s.data[i]...)
	}
	return trustverify.StagedMaterial{Operation: s.Operation(), Request: s.Request(), Content: append([]trustverify.ContentEntry(nil), s.entries...), ContentBytes: data, ToolBytes: s.toolchain.Driver(), ToolOptions: append([]string(nil), request.Action.Argv[1:]...), Environment: ProjectBuildEnvironment()}, s.toolchain, nil
}

// ValidateProjectBuildDeclaration is a pure, source-bound admission check for
// inert native resource planning. It never reads a host tool or grants execution.
// Resource admission can accept this declaration only; the runtime still verifies
// CAS bytes, project images, policy and persistent approval before any process.
func ValidateProjectBuildDeclaration(snapshot *trustverify.SourceSnapshot, tpl *manifest.Template) error {
	if snapshot == nil || tpl == nil {
		return ErrProjectBuild
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return ErrProjectBuild
	}
	if _, err := requireNativeContract(snapshot.ContractBytes(), raw); err != nil {
		return ErrProjectBuild
	}
	return ValidateBoundProjectBuildContent(snapshot, tpl)
}

// ValidateBoundProjectBuildContent checks only retained source content and the
// exact parsed manifest. Native contract admission remains the caller's separate
// versioned gate; this function provides no runtime or execution capability.
func ValidateBoundProjectBuildContent(snapshot *trustverify.SourceSnapshot, tpl *manifest.Template) error {
	if snapshot == nil || tpl == nil {
		return ErrProjectBuild
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return ErrProjectBuild
	}
	bound, err := manifest.ParseTemplate(raw)
	if err != nil || !reflect.DeepEqual(bound, tpl) {
		return ErrProjectBuild
	}
	if len(tpl.Commands) == 0 {
		return nil
	}
	if len(tpl.Commands) != 1 {
		return ErrProjectBuild
	}
	c, ok := tpl.Commands["build"]
	if !ok || c.Run != strings.Join(ProjectBuildArguments(), " ") {
		return ErrProjectBuild
	}
	action, ok := snapshot.Blob(ProjectBuildActionPath)
	if !ok {
		return ErrProjectBuild
	}
	index, ok := snapshot.Blob(trustload.ToolchainIndexPath)
	if !ok {
		return ErrProjectBuild
	}
	if err := validateProjectBuildRecord(action, index); err != nil {
		return err
	}
	var a ProjectBuildAction
	decodeProjectBuildAction(action, &a)
	if a.APIVersion == "tplaiter.dev/project-build-action/v2" || a.APIVersion == "tplaiter.dev/project-build-action/v3" {
		indexDigest := a.ModuleIndexSHA256
		if a.APIVersion == "tplaiter.dev/project-build-action/v3" {
			indexDigest = a.Variants[1].ModuleIndexSHA256
		}
		raw, ok := snapshot.Blob(trustload.GoModuleIndexPath)
		if !ok || trustload.ValidateGoModuleIndex(raw) != nil || evidencecas.Digest(raw) != indexDigest {
			return ErrProjectBuild
		}
	}
	return nil
}
func validateProjectBuildRecord(raw, index []byte) error {
	if err := trustload.ValidateGoToolchainIndex(index); err != nil {
		return err
	}
	var a ProjectBuildAction
	if len(raw) > 1<<20 || len(index) == 0 || len(index) > 8<<20 || decodeProjectBuildAction(raw, &a) != nil || !validProjectBuildVersion(a) || a.CommandName != "build" || !reflect.DeepEqual(a.Argv, ProjectBuildArguments()) || a.TimeoutMillis < 1 || a.TimeoutMillis > 120000 || a.ToolchainIndexSHA256 != evidencecas.Digest(index) {
		return ErrProjectBuild
	}
	return nil
}

// ValidateProjectBuildSource admits only declarations from a freshly verified
// closed selection. It supplies no execution authorization or host tool bytes.
func ValidateProjectBuildSource(ctx context.Context, runtime *trustverify.Runtime, input []byte, tpl *manifest.Template) error {
	if ctx == nil || runtime == nil {
		return ErrProjectBuild
	}
	selected, err := DecodeSourceSelection(input)
	if err != nil {
		return err
	}
	resolution, err := runtime.VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		return err
	}
	snapshot, err := runtime.VerifiedSnapshot(resolution)
	if err != nil {
		return err
	}
	return ValidateProjectBuildDeclaration(snapshot, tpl)
}

// decodeProjectBuildAction preserves v3 wire presence before accepting values.
// Both source admission and operation preparation use this closed decoder.
func decodeProjectBuildAction(raw []byte, action *ProjectBuildAction) error {
	if err := canonicaljson.DecodeStrict(raw, action); err != nil {
		return err
	}
	if !validProjectBuildVersion(*action) {
		return ErrProjectBuild
	}
	if action.APIVersion != "tplaiter.dev/project-build-action/v3" {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ErrProjectBuild
	}
	required := func(object map[string]json.RawMessage, keys ...string) bool {
		for _, key := range keys {
			value, ok := object[key]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return false
			}
		}
		return true
	}
	if _, present := fields["moduleIndexSHA256"]; present {
		return ErrProjectBuild
	}
	if !required(fields, "apiVersion", "adapter", "commandName", "argv", "timeoutMillis", "toolchainIndexSHA256", "genBuild", "selector", "variants") {
		return ErrProjectBuild
	}
	var variants []map[string]json.RawMessage
	if err := json.Unmarshal(fields["variants"], &variants); err != nil || len(variants) != 2 {
		return ErrProjectBuild
	}
	for i, variant := range variants {
		if !required(variant, "id", "workflow", "policy") {
			return ErrProjectBuild
		}
		if i == 0 {
			if _, present := variant["moduleIndexSHA256"]; present {
				return ErrProjectBuild
			}
			if !required(variant, "goModSHA256", "goSumSHA256") {
				return ErrProjectBuild
			}
		} else {
			if _, present := variant["goModSHA256"]; present {
				return ErrProjectBuild
			}
			if _, present := variant["goSumSHA256"]; present {
				return ErrProjectBuild
			}
			if !required(variant, "moduleIndexSHA256") {
				return ErrProjectBuild
			}
		}
	}
	return nil
}

func validBuildDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validProjectBuildVersion(a ProjectBuildAction) bool {
	if a.APIVersion == "tplaiter.dev/project-build-action/v3" {
		if a.Adapter != "go-project-build-v3" || a.Selector != "workflow" || a.ModuleIndexSHA256 != "" || len(a.Variants) != 2 || !a.GenBuild {
			return false
		}
		f, t := a.Variants[0], a.Variants[1]
		return f.ID == "workflow-false" && !f.Workflow && f.Policy == "zero-external-modules" && validBuildDigest(f.GoModSHA256) && validBuildDigest(f.GoSumSHA256) && f.ModuleIndexSHA256 == "" && t.ID == "workflow-true" && t.Workflow && t.Policy == "module-closure" && validBuildDigest(t.ModuleIndexSHA256) && t.GoModSHA256 == "" && t.GoSumSHA256 == ""
	}
	if a.Selector != "" || len(a.Variants) != 0 {
		return false
	}
	return (a.APIVersion == "tplaiter.dev/project-build-action/v1" && a.Adapter == "go-project-build-v1" && a.ModuleIndexSHA256 == "" && !a.GenBuild) || (a.APIVersion == "tplaiter.dev/project-build-action/v2" && a.Adapter == "go-project-build-v2" && len(a.ModuleIndexSHA256) == 71 && strings.HasPrefix(a.ModuleIndexSHA256, "sha256:"))
}

// projectBuildAnswers observes identity-checked current marker bytes. The
// observation supplies no execution authority: the exact marker and derived
// variant enter the operator-signed request, and are compared again at spawn.
func projectBuildAnswers(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, tpl *manifest.Template) (settings.Values, string, string, error) {
	inventory, err := stateledger.VerifyStable(ctx, owner.ProjectContext().RootPath, owner.TrustRuntime(), stateledger.StableVerifyOptions{})
	if err != nil {
		return nil, "", "", err
	}
	entries, data, err := captureProjectBuild(ctx, owner.ProjectContext().RootPath)
	if err != nil {
		return nil, "", "", err
	}
	var markerRaw, lockRaw []byte
	for i, f := range entries {
		if f.Path == ".tplaiter/project.yaml" {
			markerRaw = data[i]
		}
		if f.Path == ".tplaiter/root-template.lock.json" {
			lockRaw = data[i]
		}
	}
	digest := evidencecas.Digest(markerRaw)
	observed := false
	for _, f := range inventory.Entries {
		if f.Scope == "project" && f.Path == ".tplaiter/project.yaml" && f.SHA256 == digest {
			observed = true
		}
	}
	if !observed {
		return nil, "", "", ErrProjectBuild
	}
	var marker stateledger.ProjectV2
	dec := yaml.NewDecoder(bytes.NewReader(markerRaw))
	dec.KnownFields(true)
	if dec.Decode(&marker) != nil || marker.ID != owner.ProjectContext().ProjectID || marker.APIVersion != stateledger.ProjectV2APIVersion || marker.Template.ResolvedCommit != source.Subject().Commit || marker.Template.RequestedRef != source.Subject().RequestedRef {
		return nil, "", "", ErrProjectBuild
	}
	lock, err := provenance.DecodeRootTemplateLock(lockRaw)
	if err != nil {
		return nil, "", "", ErrProjectBuild
	}
	r := lock.Root
	if (trustverify.Subject{Origin: r.Origin, TemplatePath: r.TemplatePath, RequestedRef: r.RequestedRef, Commit: r.Commit, TreeSHA256: r.TreeSHA256, ContractSHA256: r.ContractSHA256}) != source.Subject() {
		return nil, "", "", ErrProjectBuild
	}
	answer, ok := marker.Answers["workflow"]
	if !ok {
		return nil, "", "", ErrProjectBuild
	}
	if _, ok := answer.Value.(bool); !ok {
		return nil, "", "", ErrProjectBuild
	}
	values := settings.Values{}
	for k, a := range marker.Answers {
		values[k] = a.Value
	}
	resolved, err := settings.ResolveRecorded(tpl, values, values)
	if err != nil {
		return nil, "", "", err
	}
	return resolved.Values, digest, evidencecas.Digest(lockRaw), nil
}
func checkVariantMarker(entries []trustverify.ContentEntry, data [][]byte, markerDigest, lockDigest string) error {
	marker, lock := false, false
	for i, f := range entries {
		if f.Root != "project" {
			continue
		}
		switch f.Path {
		case ".tplaiter/project.yaml":
			marker = f.ContentSHA256 == markerDigest && evidencecas.Digest(data[i]) == markerDigest
		case ".tplaiter/root-template.lock.json":
			lock = f.ContentSHA256 == lockDigest && evidencecas.Digest(data[i]) == lockDigest
		}
	}
	if !marker || !lock {
		return ErrProjectBuild
	}
	return nil
}

// ProjectVariantFor exposes only the binding from this owner's exact opaque
// selection; callers cannot inject a variant or reuse it for another request.
func (m *ExecutionMaterial) ProjectVariantFor(owner *trustload.Runtime, request trustverify.ExecutionRequest) (string, string, error) {
	if m == nil || m.projectBuild == nil || m.projectBuild.owner != owner || !reflect.DeepEqual(request, m.projectBuild.request) {
		return "", "", ErrProjectBuild
	}
	s := m.projectBuild
	if s.variant == nil {
		return "", "", nil
	}
	return s.variant.Variant.ID, evidencecas.Digest(s.variantRaw), nil
}
func (m *ExecutionMaterial) ProjectModulesFor(ctx context.Context, owner *trustload.Runtime, request trustverify.ExecutionRequest) (*trustload.GoModules, error) {
	if ctx == nil || m == nil || m.projectBuild == nil || m.projectBuild.owner != owner || !reflect.DeepEqual(request, m.projectBuild.request) {
		return nil, ErrProjectBuild
	}
	// ProjectBuildFor rechecks the whole selection immediately before this accessor.
	return m.projectBuild.modules, nil
}

func projectedBuildInputs(images map[string][]byte) ([]trustverify.ContentEntry, [][]byte, error) {
	keys := []string{}
	var total int64
	for name, b := range images {
		if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00:") {
			return nil, nil, ErrProjectBuild
		}
		parts := strings.Split(name, "/")
		skip := false
		for i, p := range parts {
			if strings.HasPrefix(p, "_") || (strings.HasPrefix(p, ".") && !(i == 0 && p == ".tplaiter")) {
				skip = true
			}
			if p == "vendor" || p == "go.work" {
				return nil, nil, ErrProjectBuild
			}
		}
		if skip {
			continue
		}
		if strings.HasPrefix(name, ".tplaiter/") {
			if name != ".tplaiter/project.yaml" && name != ".tplaiter/root-template.lock.json" && name != ".tplaiter/resources.lock.json" {
				continue
			}
		} else if !strings.HasSuffix(name, ".go") && name != "go.mod" && name != "go.sum" {
			continue
		}
		if len(b) > 16<<20 {
			return nil, nil, ErrProjectBuild
		}
		total += int64(len(b))
		if total > 64<<20 || len(keys) >= 4093 {
			return nil, nil, ErrProjectBuild
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	entries := []trustverify.ContentEntry{}
	data := [][]byte{}
	for _, name := range keys {
		b := append([]byte(nil), images[name]...)
		entries = append(entries, trustverify.ContentEntry{Root: "project", Path: name, Mode: "100644", ContentSHA256: evidencecas.Digest(b)})
		data = append(data, b)
	}
	return entries, data, nil
}
