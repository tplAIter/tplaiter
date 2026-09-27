package operationtrust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"regexp"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var rendererToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
var digestToken = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PrepareNewInput contains only untrusted source transport and non-authority
// render settings. Scratch and project roots come exclusively from Runtime.
type PrepareNewInput struct {
	SourceInput     []byte
	Render          renderref.Input
	RendererVersion string
}

// PreparedNew is an opaque, in-memory preview. It deliberately has no JSON
// decoder, execution method, publication method, or fabricated source pair.
type PreparedNew struct {
	root       provenance.RootTemplateLock
	deps       provenance.TemplateLock
	rendered   *renderref.Result
	operation  string
	runtime    *trustverify.Runtime
	resolution *trustverify.VerifiedResolution
}

// PrepareUpdateInput retains independently verified source and target inputs.
// PreimageSHA256 must be computed by the lifecycle owner from its bounded,
// read-only project scan before calling preparation.
type PrepareUpdateInput struct {
	SourceInput, TargetInput []byte
	Render                   renderref.Input
	RendererVersion          string
	PreimageSHA256           string
}
type PreparedUpdate struct {
	source, target                     provenance.RootTemplateLock
	sourceDeps, targetDeps             provenance.TemplateLock
	rendered                           *renderref.Result
	operation                          string
	runtime                            *trustverify.Runtime
	sourceResolution, targetResolution *trustverify.VerifiedResolution
}

func (p *PreparedUpdate) ValidFor(runtime *trustverify.Runtime) bool {
	return p != nil && runtime != nil && runtime == p.runtime && p.sourceResolution.ValidFor(runtime, runtime.Binding()) && p.targetResolution.ValidFor(runtime, runtime.Binding()) && provenance.ValidateLockPair(p.source, p.sourceDeps) == nil && provenance.ValidateLockPair(p.target, p.targetDeps) == nil && p.source.TrustProfile.Equal(runtime.Binding()) && p.target.TrustProfile.Equal(runtime.Binding()) && p.operation != ""
}
func (p *PreparedUpdate) SourceRootLock() provenance.RootTemplateLock {
	if p == nil {
		return provenance.RootTemplateLock{}
	}
	return p.source
}
func (p *PreparedUpdate) TargetRootLock() provenance.RootTemplateLock {
	if p == nil {
		return provenance.RootTemplateLock{}
	}
	return p.target
}
func (p *PreparedUpdate) SourceDependencyLock() provenance.TemplateLock {
	if p == nil {
		return provenance.TemplateLock{}
	}
	return p.sourceDeps
}
func (p *PreparedUpdate) TargetDependencyLock() provenance.TemplateLock {
	if p == nil {
		return provenance.TemplateLock{}
	}
	return p.targetDeps
}
func (p *PreparedUpdate) OperationInputsSHA256() string {
	if p == nil {
		return ""
	}
	return p.operation
}
func (p *PreparedUpdate) Rendered() *renderref.Result {
	if p == nil || p.rendered == nil {
		return nil
	}
	return cloneResult(p.rendered)
}

func (p *PreparedNew) ValidFor(runtime *trustverify.Runtime) bool {
	return p != nil && runtime != nil && runtime == p.runtime && p.resolution.ValidFor(runtime, runtime.Binding()) && provenance.ValidateLockPair(p.root, p.deps) == nil && p.root.TrustProfile.Equal(runtime.Binding()) && p.operation != ""
}
func (p *PreparedNew) RootLock() provenance.RootTemplateLock {
	if p == nil {
		return provenance.RootTemplateLock{}
	}
	return p.root
}
func (p *PreparedNew) DependencyLock() provenance.TemplateLock {
	if p == nil {
		return provenance.TemplateLock{}
	}
	return p.deps
}
func (p *PreparedNew) OperationInputsSHA256() string {
	if p == nil {
		return ""
	}
	return p.operation
}
func (p *PreparedNew) Rendered() *renderref.Result {
	if p == nil || p.rendered == nil {
		return nil
	}
	return cloneResult(p.rendered)
}

// PrepareNew verifies the exact subject before touching scratch, projects an
// in-memory snapshot, rejects anything outside native empty closure, renders
// below the authenticated scratch root, and seals one target lock pair.
func PrepareNew(ctx context.Context, runtime *trustload.Runtime, in PrepareNewInput) (*PreparedNew, error) {
	if ctx == nil || runtime == nil || !rendererToken.MatchString(in.RendererVersion) {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	stable := runtime.TrustRuntime()
	project := runtime.ProjectContext()
	if stable == nil || runtime.ScratchRoot() == "" || project.ProjectID == "" || project.RootPath == "" {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	selection, err := DecodeSourceSelection(in.SourceInput)
	if err != nil {
		return nil, err
	}
	resolution, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	src, err := SnapshotFS(stable, resolution)
	if err != nil {
		return nil, err
	}
	contract, err := fs.ReadFile(src, "template.contract.json")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	manifest, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	if _, err = requireNativeContract(contract, manifest); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(src)
	if err != nil || unsupportedTemplateActions(tpl, "new") {
		return nil, ErrSourceAdapterUnsupported
	}
	result, err := renderref.RenderInScratch(ctx, src, in.Render, runtime.ScratchRoot())
	if err != nil {
		return nil, err
	}
	root, deps, err := projectNativeLockPair(stable, resolution, in.RendererVersion)
	if err != nil {
		return nil, err
	}
	operation, err := emptyOperation(stable, resolution, project.ProjectID, "new", in.Render.Values)
	if err != nil {
		return nil, err
	}
	// Freshly re-verify proof locators and full binding before handing out even
	// an in-memory preview. The retained result is discarded on drift.
	fresh, err := stable.VerifySubject(ctx, selection.TrustSubject(), selection.EvidenceRefs())
	if err != nil || fresh.Subject() != resolution.Subject() || fresh.Evidence() != resolution.Evidence() || !fresh.ValidFor(stable, stable.Binding()) {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	return &PreparedNew{root: root, deps: deps, rendered: cloneResult(result), operation: operation, runtime: stable, resolution: resolution}, nil
}

// PrepareUpdate preserves two independently verified lock pairs; it never
// reuses a target as a fictitious source and it emits no UpdatePlan for the
// empty-action preview boundary.
func PrepareUpdate(ctx context.Context, runtime *trustload.Runtime, in PrepareUpdateInput) (*PreparedUpdate, error) {
	if ctx == nil || runtime == nil || !rendererToken.MatchString(in.RendererVersion) || !digestToken.MatchString(in.PreimageSHA256) {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	stable, project := runtime.TrustRuntime(), runtime.ProjectContext()
	if stable == nil || runtime.ScratchRoot() == "" || project.ProjectID == "" || project.RootPath == "" {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	source, err := DecodeSourceSelection(in.SourceInput)
	if err != nil {
		return nil, err
	}
	target, err := DecodeSourceSelection(in.TargetInput)
	if err != nil {
		return nil, err
	}
	sourceResolution, err := stable.VerifySubject(ctx, source.TrustSubject(), source.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	targetResolution, err := stable.VerifySubject(ctx, target.TrustSubject(), target.EvidenceRefs())
	if err != nil {
		return nil, err
	}
	sourceFS, err := SnapshotFS(stable, sourceResolution)
	if err != nil {
		return nil, err
	}
	targetFS, err := SnapshotFS(stable, targetResolution)
	if err != nil {
		return nil, err
	}
	sourceContract, err := fs.ReadFile(sourceFS, "template.contract.json")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	sourceManifest, err := fs.ReadFile(sourceFS, "template.manifest.yaml")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	targetContract, err := fs.ReadFile(targetFS, "template.contract.json")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	targetManifest, err := fs.ReadFile(targetFS, "template.manifest.yaml")
	if err != nil {
		return nil, ErrSourceAdapterUnsupported
	}
	if _, err = requireNativeContract(sourceContract, sourceManifest); err != nil {
		return nil, err
	}
	if _, err = requireNativeContract(targetContract, targetManifest); err != nil {
		return nil, err
	}
	tpl, err := renderref.LoadTemplate(targetFS)
	if err != nil || unsupportedTemplateActions(tpl, "update") {
		return nil, ErrSourceAdapterUnsupported
	}
	result, err := renderref.RenderInScratch(ctx, targetFS, in.Render, runtime.ScratchRoot())
	if err != nil {
		return nil, err
	}
	sourceRoot, sourceDeps, err := projectNativeLockPair(stable, sourceResolution, in.RendererVersion)
	if err != nil {
		return nil, err
	}
	targetRoot, targetDeps, err := projectNativeLockPair(stable, targetResolution, in.RendererVersion)
	if err != nil {
		return nil, err
	}
	op, err := emptyUpdateOperation(stable, sourceResolution, targetResolution, project.ProjectID, in.PreimageSHA256, in.Render.Values)
	if err != nil {
		return nil, err
	}
	freshSource, err := stable.VerifySubject(ctx, source.TrustSubject(), source.EvidenceRefs())
	if err != nil || freshSource.Subject() != sourceResolution.Subject() || freshSource.Evidence() != sourceResolution.Evidence() {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	freshTarget, err := stable.VerifySubject(ctx, target.TrustSubject(), target.EvidenceRefs())
	if err != nil || freshTarget.Subject() != targetResolution.Subject() || freshTarget.Evidence() != targetResolution.Evidence() {
		return nil, errors.New("TRUST_APPROVAL_MISMATCH")
	}
	return &PreparedUpdate{source: sourceRoot, target: targetRoot, sourceDeps: sourceDeps, targetDeps: targetDeps, rendered: cloneResult(result), operation: op, runtime: stable, sourceResolution: sourceResolution, targetResolution: targetResolution}, nil
}

// projectNativeLockPair projects immutable proof from a runtime-bound opaque
// resolution. Caller-decoded locks, profile assertions, and non-native closure
// cannot enter this boundary.
func projectNativeLockPair(runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, rendererVersion string) (provenance.RootTemplateLock, provenance.TemplateLock, error) {
	if runtime == nil || resolution == nil || !resolution.ValidFor(runtime, runtime.Binding()) || !rendererToken.MatchString(rendererVersion) {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errors.New("TRUST_RUNTIME_INVALID")
	}
	src, err := SnapshotFS(runtime, resolution)
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	contract, err := fs.ReadFile(src, "template.contract.json")
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, ErrSourceAdapterUnsupported
	}
	manifest, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, ErrSourceAdapterUnsupported
	}
	if _, err := requireNativeContract(contract, manifest); err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	binding := runtime.Binding()
	s, e := resolution.Subject(), resolution.Evidence()
	root := provenance.RootTemplateLock{APIVersion: provenance.RootTemplateLockAPIVersion, Kind: provenance.RootTemplateLockKind, TrustProfile: binding, Policy: provenance.PolicyBinding{PolicySHA256: binding.PolicySHA256}, Root: provenance.RootSubjectFromTrust(s, bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS), Renderer: provenance.RendererIdentity{Name: "go-text-template", Version: rendererVersion}}
	root.RootLockSHA256, err = provenance.ComputeRootLockSHA256(root)
	if err != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, err
	}
	deps := provenance.TemplateLock{APIVersion: provenance.TemplateLockAPIVersion, Kind: provenance.DependencyExportLockKind, TrustProfile: binding, RootLockSHA256: root.RootLockSHA256, Dependencies: []provenance.DependencySubject{}}
	deps.LockSHA256, err = provenance.ComputeTemplateLockSHA256(deps)
	if err != nil || provenance.ValidateLockPair(root, deps) != nil {
		return provenance.RootTemplateLock{}, provenance.TemplateLock{}, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	return root, deps, nil
}

func emptyOperation(runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, projectID, scope string, values any) (string, error) {
	if runtime == nil || resolution == nil || projectID == "" || (scope != "new" && scope != "update") {
		return "", errors.New("TRUST_RUNTIME_INVALID")
	}
	bindingRaw, err := canonicaljson.Canonical(runtime.Binding())
	if err != nil {
		return "", err
	}
	bindingHash := digestWithDomain(bootstrap.ProfileBindingAPIVersion, bindingRaw)
	valuesRaw, err := canonicaljson.Canonical(values)
	if err != nil {
		return "", err
	}
	s := resolution.Subject()
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bindingHash, ProjectID: projectID, Scope: scope, PreimageSHA256: rawDigest(nil), AnswersSHA256: rawDigest(valuesRaw), Subjects: []trustverify.Provider{{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}, Actions: []trustverify.ActionMaterial{}}
	return trustverify.ComputeOperationInputsSHA256(op)
}

func emptyUpdateOperation(runtime *trustverify.Runtime, source, target *trustverify.VerifiedResolution, projectID, preimage string, values any) (string, error) {
	if runtime == nil || source == nil || target == nil || projectID == "" || !digestToken.MatchString(preimage) {
		return "", errors.New("TRUST_RUNTIME_INVALID")
	}
	bindingRaw, err := canonicaljson.Canonical(runtime.Binding())
	if err != nil {
		return "", err
	}
	valuesRaw, err := canonicaljson.Canonical(values)
	if err != nil {
		return "", err
	}
	providers := []trustverify.Provider{providerFromSubject(source.Subject()), providerFromSubject(target.Subject())}
	if providerKey(providers[1]) < providerKey(providers[0]) {
		providers[0], providers[1] = providers[1], providers[0]
	}
	if providers[0] == providers[1] {
		providers = providers[:1]
	}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: digestWithDomain(bootstrap.ProfileBindingAPIVersion, bindingRaw), ProjectID: projectID, Scope: "update", PreimageSHA256: preimage, AnswersSHA256: rawDigest(valuesRaw), Subjects: providers, Actions: []trustverify.ActionMaterial{}}
	return trustverify.ComputeOperationInputsSHA256(op)
}
func providerFromSubject(s trustverify.Subject) trustverify.Provider {
	return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}
func providerKey(p trustverify.Provider) string {
	return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit
}

// T5 has no command-material provider. Every currently reachable hook, tool
// requirement and environment setup is therefore observed and denied before
// scratch allocation rather than silently omitted or delegated to a runner.
func unsupportedTemplateActions(tpl *manifest.Template, scope string) bool {
	if tpl == nil || len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 {
		return true
	}
	if scope == "new" {
		return len(tpl.Hooks.PostCreate) != 0
	}
	return scope == "update" && len(tpl.Hooks.PostUpdate) != 0
}

func digestWithDomain(domain string, raw []byte) string {
	h := sha256.Sum256(append(append([]byte(domain), 0), raw...))
	return "sha256:" + hex.EncodeToString(h[:])
}

func cloneResult(in *renderref.Result) *renderref.Result {
	if in == nil {
		return nil
	}
	out := *in
	out.Files = make(map[string][]byte, len(in.Files))
	for k, v := range in.Files {
		out.Files[k] = append([]byte(nil), v...)
	}
	return &out
}
