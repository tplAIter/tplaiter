package trustverify

import (
	"context"
	"errors"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

type (
	ProjectContext       struct{ ProjectID, SubmitterPrincipalID, MinimumProfile string }
	ProjectContextReader interface {
		Load(context.Context) (ProjectContext, error)
	}
)

type ExecutionPolicySnapshot struct {
	PolicyJSON           []byte
	ExpectedPolicySHA256 string
}
type ExternalExecutionPolicyReader interface {
	Load(context.Context) (ExecutionPolicySnapshot, error)
}
type AuthorityBundleReader interface {
	Load(context.Context) (bootstrap.Bundle, error)
}
type StableOptions struct {
	Profile   bootstrap.ProfileID
	Project   ProjectContextReader
	Policy    ExternalExecutionPolicyReader
	External  bootstrap.ExternalAuthorityReader
	Bundle    AuthorityBundleReader
	Protected bootstrap.ProtectedReader
	Evidence  evidencecas.Reader
	Objects   GitObjectReader
	Clock     bootstrap.Clock
	// Human is accepted only for a directly composed interactive CLI runtime.
	// No transport string supplied by request material can enable it.
	Transport string
	Human     HumanReviewer
}
type EvidenceRefs struct {
	Format, StatementCAS, SignatureCAS, KeyFingerprint, CheckpointCAS, InclusionProofCAS string
}
type Runtime struct {
	options StableOptions
	binding bootstrap.ProfileBinding
	marker  *runtimeMarker
}

type ExecutionPermit struct {
	marker      *runtimeMarker
	binding     bootstrap.ProfileBinding
	resolution  *VerifiedResolution
	operation   OperationInputs
	request     ExecutionRequest
	approval    ApprovalRefs
	grantSHA256 string
	human       *HumanApproval
	expires     time.Time
}

// PersistentApprovalReference is public evidence for a sealed plan, not a
// capability. Only Runtime.PersistentApprovalReference can derive it from an
// opaque, runtime-local persistent permit.
type PersistentApprovalReference struct {
	RequestSHA256 string
	GrantSHA256   string
	ApprovalCAS   string
}

type HumanApproval struct {
	marker    *runtimeMarker
	binding   bootstrap.ProfileBinding
	projectID string
	request   string
	operation string
	expires   time.Time
}

type PermitSummary struct {
	RequestSHA256, OperationInputsSHA256, ExpiresAt string
}

func (p *ExecutionPermit) Summary() PermitSummary {
	if p == nil || p.marker == nil {
		return PermitSummary{}
	}
	return PermitSummary{p.request.RequestSHA256, p.operationDigest(), p.expires.UTC().Format(time.RFC3339)}
}

func (p *ExecutionPermit) operationDigest() string {
	d, err := ComputeOperationInputsSHA256(p.operation)
	if err != nil {
		return ""
	}
	return d
}

// A non-zero-size marker is required: Go may coalesce pointers to zero-size
// allocations, which would let two independently constructed runtimes compare
// equal by address.
type (
	runtimeMarker      struct{ instance byte } //nolint:unused // non-zero size is the point; see the comment above
	VerifiedResolution struct {
		marker                                                         *runtimeMarker
		snapshot                                                       *SourceSnapshot
		publisherIssuer, publisherPrincipalID, publisherKeyFingerprint string
		rule                                                           SourceRule
		binding                                                        bootstrap.ProfileBinding
		evidence                                                       EvidenceRefs
	}
)

// ValidFor reports whether this opaque resolution belongs to runtime's
// unchanged constructor binding. It does not manufacture authority from a
// caller-provided binding assertion.
func (r *VerifiedResolution) ValidFor(runtime *Runtime, binding bootstrap.ProfileBinding) bool {
	return r != nil && runtime != nil && r.marker != nil && r.marker == runtime.marker && r.binding.Equal(binding) && runtime.binding.Equal(binding)
}

// VerifiedSnapshot returns the snapshot already retained by a stable,
// runtime-bound resolution. SourceSnapshot's accessors own defensive copies;
// this method performs no I/O or re-verification and does not mint authority.
func (r *Runtime) VerifiedSnapshot(resolution *VerifiedResolution) (*SourceSnapshot, error) {
	if r == nil || !resolution.ValidFor(r, r.binding) || resolution.snapshot == nil {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	return resolution.snapshot, nil
}

// Evidence returns the retained proof locators by value. Strings are immutable;
// callers cannot alter the resolution's proof identity.
func (r *VerifiedResolution) Evidence() EvidenceRefs {
	if r == nil {
		return EvidenceRefs{}
	}
	return r.evidence
}

// Subject returns the verified source identity as a value copy.
func (r *VerifiedResolution) Subject() Subject {
	if r == nil || r.snapshot == nil {
		return Subject{}
	}
	return r.snapshot.Subject()
}

func NewRuntime(ctx context.Context, o StableOptions) (*Runtime, error) {
	if ctx == nil || o.Project == nil || o.Policy == nil || o.External == nil || o.Evidence == nil || o.Objects == nil || o.Clock == nil || (o.Profile != bootstrap.ProfileOSS && o.Profile != bootstrap.ProfileOrganization) || (o.Profile == bootstrap.ProfileOSS && o.Bundle == nil) || (o.Profile == bootstrap.ProfileOrganization && o.Protected == nil) || (o.Human != nil && o.Transport != "direct-interactive-cli") {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	r := &Runtime{options: o, marker: &runtimeMarker{}}
	b, _, _, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	r.binding = b
	return r, nil
}

func (r *Runtime) Binding() bootstrap.ProfileBinding {
	if r == nil {
		return bootstrap.ProfileBinding{}
	}
	return r.binding
}

func (r *Runtime) CheckBinding(b bootstrap.ProfileBinding) error {
	if r == nil || !r.binding.Equal(b) {
		return diagnostic(TrustRuntimeInvalid, nil)
	}
	return nil
}

func (r *Runtime) load(ctx context.Context) (bootstrap.ProfileBinding, *ExecutionPolicy, *bootstrap.Authority, error) {
	if r == nil || ctx == nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, err
	}
	pc, err := r.options.Project.Load(ctx)
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	ps, err := r.options.Policy.Load(ctx)
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	p, err := DecodeExecutionPolicy(ps.PolicyJSON)
	if err != nil || p.PolicySHA256 != ps.ExpectedPolicySHA256 {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	if err := validAt(p.Validity, r.options.Clock.Now().UTC()); err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	if !principalRE.MatchString(pc.SubmitterPrincipalID) || !token(pc.ProjectID) || !profile(pc.MinimumProfile) || !containsPrincipal(p, pc.SubmitterPrincipalID) || p.Profile != string(r.options.Profile) || !minimumPermits(pc.MinimumProfile, p.MinimumProfile, r.options.Profile) {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustExecutionPolicyInvalid, nil)
	}
	ext, err := bootstrap.LoadExternal(ctx, r.options.External)
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	v, err := bootstrap.NewVerifier(r.options.Evidence, r.options.Clock, nil, 0)
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	var a *bootstrap.Authority
	if r.options.Profile == bootstrap.ProfileOSS {
		b, e := r.options.Bundle.Load(ctx)
		if e != nil {
			return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, e)
		}
		a, err = v.VerifyOSS(ctx, ext, b)
	} else {
		a, err = v.VerifyOrganization(ctx, ext, r.options.Protected)
	}
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	bb := a.Binding()
	cfg, err := bootstrap.DomainDigest("tplaiter.dev/runtime-effective-config/v1", map[string]any{"apiVersion": "tplaiter.dev/runtime-effective-config/v1", "profile": string(r.options.Profile), "bootstrapConfigSHA256": bb.ConfigSHA256, "executionPolicySHA256": p.PolicySHA256, "minimumProfile": pc.MinimumProfile, "projectID": pc.ProjectID, "submitterPrincipalID": pc.SubmitterPrincipalID, "sourceDigestVersion": "tplaiter.dev/source-content-tree/v1", "contractDigestVersion": "tplaiter.dev/source-contract/v1", "proofFormat": "tplaiter-publisher-statement-v1", "artifactProof": "statement-cas-in-authority-checkpoint"})
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	pol, err := bootstrap.DomainDigest("tplaiter.dev/runtime-policy/v1", map[string]any{"apiVersion": "tplaiter.dev/runtime-policy/v1", "bootstrapPolicySHA256": bb.PolicySHA256, "executionPolicySHA256": p.PolicySHA256})
	if err != nil {
		return bootstrap.ProfileBinding{}, nil, nil, diagnostic(TrustRuntimeInvalid, err)
	}
	return bootstrap.ProfileBinding{APIVersion: bootstrap.ProfileBindingAPIVersion, ID: bb.ID, DefinitionVersion: 1, ConfigSHA256: cfg, PolicySHA256: pol, AuthoritySHA256: bb.AuthoritySHA256, Assurance: bb.Assurance, EvidenceClass: bb.EvidenceClass}, p, a, nil
}

func (r *Runtime) VerifySubject(ctx context.Context, s Subject, refs EvidenceRefs) (*VerifiedResolution, error) {
	if r == nil || ctx == nil || refs.Format != bootstrap.PublisherStatementAPIVersion || !validDigest(refs.StatementCAS) || !validDigest(refs.SignatureCAS) || !validDigest(refs.KeyFingerprint) || !validDigest(refs.CheckpointCAS) || !validDigest(refs.InclusionProofCAS) {
		return nil, diagnostic(TrustSubjectInvalid, nil)
	}
	b, p, a, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	if !b.Equal(r.binding) {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	snap, err := VerifySource(ctx, r.options.Objects, s)
	if err != nil {
		return nil, diagnostic(TrustSubjectInvalid, err)
	}
	rule, ok := matchingRule(p, s)
	if !ok {
		return nil, diagnostic(TrustSubjectInvalid, nil)
	}
	v, err := bootstrap.NewVerifier(r.options.Evidence, r.options.Clock, nil, 0)
	if err != nil {
		return nil, diagnostic(TrustRuntimeInvalid, err)
	}
	x := bootstrap.PublisherExpectation{PolicyOrigin: rule.PolicyOrigin, Issuer: rule.Issuer, Predicate: rule.Predicate, Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}
	c, err := v.VerifyPublisherClaim(ctx, a, x, bootstrap.PublisherEvidence{StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint})
	if err != nil || c == nil || c.Expectation() != x || c.AuthoritySHA256() != a.Binding().AuthoritySHA256 {
		return nil, diagnostic(TrustSubjectInvalid, err)
	}
	if err = bootstrap.VerifyArtifactTransparency(ctx, a, r.options.Evidence, refs.StatementCAS, bootstrap.TransparencyEvidence{CheckpointCAS: refs.CheckpointCAS, InclusionProofCAS: refs.InclusionProofCAS}); err != nil {
		return nil, diagnostic(TrustEvidenceTampered, err)
	}
	b2, _, _, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	if !b2.Equal(r.binding) {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	principal, ok := issuerPrincipal(p, rule.Issuer)
	if !ok {
		return nil, diagnostic(TrustExecutionPolicyInvalid, nil)
	}
	return &VerifiedResolution{marker: r.marker, snapshot: snap, publisherIssuer: rule.Issuer, publisherPrincipalID: principal, publisherKeyFingerprint: refs.KeyFingerprint, rule: rule, binding: r.binding, evidence: refs}, nil
}

func containsPrincipal(p *ExecutionPolicy, id string) bool {
	for _, x := range p.Principals {
		if x.ID == id {
			return true
		}
	}
	return false
}

func issuerPrincipal(p *ExecutionPolicy, issuer string) (string, bool) {
	for _, x := range p.IssuerPrincipals {
		if x.Issuer == issuer {
			return x.PrincipalID, true
		}
	}
	return "", false
}

func matchingRule(p *ExecutionPolicy, s Subject) (SourceRule, bool) {
	var match SourceRule
	found := false
	for _, x := range p.SourceRules {
		if x.Origin == s.Origin && x.TemplatePath == s.TemplatePath {
			// EvidenceRefs do not select issuer or predicate. Multiple rules for
			// one source locator would otherwise make slice order authority.
			if found {
				return SourceRule{}, false
			}
			match, found = x, true
		}
	}
	return match, found
}

func runtimeBindingDigest(b bootstrap.ProfileBinding) (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	return approvalDigest(bootstrap.ProfileBindingAPIVersion, b)
}

func exactOperationFor(r ExecutionRequest, o OperationInputs) error {
	d, err := ComputeOperationInputsSHA256(o)
	if err != nil || d != r.OperationInputsSHA256 || o.ProfileBindingSHA256 != r.ProfileBindingSHA256 || o.ProjectID != r.ProjectID || o.Scope != r.Scope {
		return diagnostic(TrustRequestInvalid, nil)
	}
	foundSubject, foundAction := false, false
	for _, p := range o.Subjects {
		if p == r.Provider {
			foundSubject = true
			break
		}
	}
	for _, a := range o.Actions {
		if a.Provider == r.Provider && sameAction(a.Action, r.Action) && a.Tool == r.Tool && a.WorkingDirectoryScope == r.WorkingDirectoryScope && a.EnvironmentPolicySHA256 == r.EnvironmentPolicySHA256 && a.TimeoutMillis == r.TimeoutMillis && a.Migration == r.Migration {
			foundAction = true
			break
		}
	}
	if !foundSubject || !foundAction {
		return diagnostic(TrustRequestInvalid, nil)
	}
	return nil
}

func sameAction(a, b Action) bool {
	if a.ID != b.ID || a.Kind != b.Kind || a.Phase != b.Phase || a.Shell != b.Shell || a.ContentClosureSHA256 != b.ContentClosureSHA256 || len(a.Argv) != len(b.Argv) {
		return false
	}
	for i := range a.Argv {
		if a.Argv[i] != b.Argv[i] {
			return false
		}
	}
	return true
}

func subjectProvider(s Subject) Provider {
	return Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func cloneRequest(r ExecutionRequest) ExecutionRequest {
	r.Action.Argv = append([]string(nil), r.Action.Argv...)
	return r
}

func cloneOperation(o OperationInputs) OperationInputs {
	o.Subjects = append([]Provider(nil), o.Subjects...)
	o.Actions = append([]ActionMaterial(nil), o.Actions...)
	for i := range o.Actions {
		o.Actions[i].Action.Argv = append([]string(nil), o.Actions[i].Action.Argv...)
	}
	return o
}

func sameRequest(a, b ExecutionRequest) bool {
	if a.RequestSHA256 == "" || a.RequestSHA256 != b.RequestSHA256 {
		return false
	}
	return a.VerifyRequestSHA256() == nil && b.VerifyRequestSHA256() == nil
}

func (r *Runtime) currentResolution(ctx context.Context, old *VerifiedResolution) (*VerifiedResolution, *ExecutionPolicy, ProjectContext, error) {
	if r == nil || old == nil || !old.ValidFor(r, r.binding) {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, nil)
	}
	b, p, _, err := r.load(ctx)
	if err != nil || !b.Equal(r.binding) {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, err)
	}
	pc, err := r.options.Project.Load(ctx)
	if err != nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, err)
	}
	fresh, err := r.VerifySubject(ctx, old.Subject(), old.Evidence())
	if err != nil {
		return nil, nil, ProjectContext{}, err
	}
	if fresh.publisherIssuer != old.publisherIssuer || fresh.publisherPrincipalID != old.publisherPrincipalID || fresh.publisherKeyFingerprint != old.publisherKeyFingerprint || fresh.rule != old.rule {
		return nil, nil, ProjectContext{}, diagnostic(TrustApprovalMismatch, nil)
	}
	return fresh, p, pc, nil
}

func policyApprover(ctx context.Context, store evidencecas.Reader, policy *ExecutionPolicy, refs ApprovalRefs) (*ExecutionApproval, *Approver, error) {
	if refs.Kind != "persistent-signed" || !validDigest(refs.ApprovalCAS) {
		return nil, nil, diagnostic(TrustApprovalRequired, nil)
	}
	raw, err := store.Read(ctx, refs.ApprovalCAS)
	if err != nil {
		return nil, nil, diagnostic(TrustEvidenceMissing, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(raw) > maxApprovalJSON || evidencecas.Digest(raw) != refs.ApprovalCAS {
		return nil, nil, diagnostic(TrustEvidenceTampered, nil)
	}
	a, err := DecodeExecutionApproval(raw)
	if err != nil {
		return nil, nil, diagnostic(TrustApprovalMismatch, err)
	}
	for i := range policy.Approvers {
		if policy.Approvers[i].ID == a.ApproverID && policy.Approvers[i].KeyFingerprint == a.KeyFingerprint {
			return a, &policy.Approvers[i], nil
		}
	}
	return nil, nil, diagnostic(TrustApprovalMismatch, nil)
}

func (r *Runtime) authorizePersistent(ctx context.Context, resolution *VerifiedResolution, operation OperationInputs, request ExecutionRequest, refs ApprovalRefs) (*ExecutionPermit, error) {
	if refs.Kind != "persistent-signed" || !validDigest(refs.ApprovalCAS) {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	if ctx == nil || !sameRequest(request, request) || exactOperationFor(request, operation) != nil {
		return nil, diagnostic(TrustRequestInvalid, nil)
	}
	bindingDigest, err := runtimeBindingDigest(r.binding)
	if err != nil || request.ProfileBindingSHA256 != bindingDigest {
		return nil, diagnostic(TrustRequestInvalid, err)
	}
	fresh, policy, project, err := r.currentResolution(ctx, resolution)
	if err != nil {
		return nil, err
	}
	if request.Provider != subjectProvider(fresh.Subject()) || request.ProjectID != project.ProjectID || request.TimeoutMillis > policy.MaxTimeoutMillis {
		return nil, diagnostic(TrustApprovalMismatch, nil)
	}
	if err := VerifyPersistentApproval(ctx, r.options.Evidence, policy, &request, request.OperationInputsSHA256, bindingDigest, r.options.Clock.Now().UTC(), refs.ApprovalCAS); err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	approval, approver, err := policyApprover(ctx, r.options.Evidence, policy, refs)
	if err != nil {
		return nil, err
	}
	if r.options.Profile == bootstrap.ProfileOrganization {
		if policy.AllowInvocationHuman || approver.PrincipalID == fresh.publisherPrincipalID || approver.PrincipalID == project.SubmitterPrincipalID || approver.KeyFingerprint == fresh.publisherKeyFingerprint {
			return nil, diagnostic(TrustApprovalMismatch, nil)
		}
	}
	// A final complete reload catches changes during grant reads and preserves the
	// authenticated policy mapping used for the separation comparison.
	final, finalPolicy, finalProject, err := r.currentResolution(ctx, fresh)
	if err != nil {
		return nil, err
	}
	if finalPolicy.PolicySHA256 != policy.PolicySHA256 || finalProject != project || final.publisherPrincipalID != fresh.publisherPrincipalID || final.publisherKeyFingerprint != fresh.publisherKeyFingerprint {
		return nil, diagnostic(TrustApprovalMismatch, nil)
	}
	_, finalApprover, err := policyApprover(ctx, r.options.Evidence, finalPolicy, refs)
	if err != nil || finalApprover.PrincipalID != approver.PrincipalID || finalApprover.KeyFingerprint != approver.KeyFingerprint {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	_, until, err := parseValidity(approval.Validity)
	if err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	return &ExecutionPermit{marker: r.marker, binding: r.binding, resolution: final, operation: cloneOperation(operation), request: cloneRequest(request), approval: refs, grantSHA256: approval.GrantSHA256, expires: until}, nil
}

// Authorize mints only a persistent-signed permit. Human approval has a typed,
// separate entry point so it cannot be smuggled through ApprovalRefs.
func (r *Runtime) Authorize(ctx context.Context, resolution *VerifiedResolution, operation OperationInputs, request ExecutionRequest, refs ApprovalRefs) (*ExecutionPermit, error) {
	if r == nil {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	return r.authorizePersistent(ctx, resolution, operation, request, refs)
}

// PersistentApprovalReference derives the persistent approval evidence
// retained by a stable permit. It intentionally does not reload authority or
// evidence: apply/continue must revalidate the sealed CAS reference freshly.
func (r *Runtime) PersistentApprovalReference(permit *ExecutionPermit) (PersistentApprovalReference, error) {
	if r == nil || permit == nil || permit.marker == nil || permit.marker != r.marker || !permit.binding.Equal(r.binding) || permit.resolution == nil || !permit.resolution.ValidFor(r, r.binding) || permit.human != nil || permit.approval.Kind != "persistent-signed" || !validDigest(permit.request.RequestSHA256) || !validDigest(permit.grantSHA256) || !validDigest(permit.approval.ApprovalCAS) || exactOperationFor(permit.request, permit.operation) != nil || !r.options.Clock.Now().UTC().Before(permit.expires) {
		return PersistentApprovalReference{}, diagnostic(TrustApprovalMismatch, nil)
	}
	return PersistentApprovalReference{RequestSHA256: permit.request.RequestSHA256, GrantSHA256: permit.grantSHA256, ApprovalCAS: permit.approval.ApprovalCAS}, nil
}

func (r *Runtime) ReviewHuman(ctx context.Context, resolution *VerifiedResolution, operation OperationInputs, request ExecutionRequest) (*HumanApproval, error) {
	if r == nil || ctx == nil || r.options.Profile != bootstrap.ProfileOSS || r.options.Transport != "direct-interactive-cli" || r.options.Human == nil || exactOperationFor(request, operation) != nil {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	bindingDigest, err := runtimeBindingDigest(r.binding)
	if err != nil || request.ProfileBindingSHA256 != bindingDigest {
		return nil, diagnostic(TrustRequestInvalid, err)
	}
	fresh, policy, project, err := r.currentResolution(ctx, resolution)
	if err != nil {
		return nil, err
	}
	if !policy.AllowInvocationHuman || request.Provider != subjectProvider(fresh.Subject()) || request.ProjectID != project.ProjectID || request.TimeoutMillis > policy.MaxTimeoutMillis {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	ok, err := r.options.Human.Review(ctx, HumanReview{request.RequestSHA256, request.OperationInputsSHA256, request.ProjectID, request.Scope})
	if err != nil {
		return nil, diagnostic(TrustApprovalRequired, err)
	}
	if !ok {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	final, finalPolicy, finalProject, err := r.currentResolution(ctx, fresh)
	if err != nil || !finalPolicy.AllowInvocationHuman || finalProject != project || subjectProvider(final.Subject()) != request.Provider {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	_, policyEnd, err := parseValidity(finalPolicy.Validity)
	if err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	expires := r.options.Clock.Now().UTC().Add(300 * time.Second)
	if policyEnd.Before(expires) {
		expires = policyEnd
	}
	return &HumanApproval{marker: r.marker, binding: r.binding, projectID: request.ProjectID, request: request.RequestSHA256, operation: request.OperationInputsSHA256, expires: expires}, nil
}

func (r *Runtime) AuthorizeHuman(ctx context.Context, resolution *VerifiedResolution, operation OperationInputs, request ExecutionRequest, human *HumanApproval) (*ExecutionPermit, error) {
	if r == nil {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	bindingDigest, digestErr := runtimeBindingDigest(r.binding)
	if digestErr != nil || request.ProfileBindingSHA256 != bindingDigest || human == nil || human.marker != r.marker || !human.binding.Equal(r.binding) || human.projectID != request.ProjectID || human.request != request.RequestSHA256 || human.operation != request.OperationInputsSHA256 || !r.options.Clock.Now().UTC().Before(human.expires) {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	// ReviewHuman's final reload is intentionally repeated here; an approval is
	// a capability, never evidence that current authority remains unchanged.
	fresh, policy, project, err := r.currentResolution(ctx, resolution)
	if err != nil || r.options.Profile != bootstrap.ProfileOSS || !policy.AllowInvocationHuman || project.ProjectID != request.ProjectID || request.Provider != subjectProvider(fresh.Subject()) || request.TimeoutMillis > policy.MaxTimeoutMillis || exactOperationFor(request, operation) != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	final, finalPolicy, finalProject, err := r.currentResolution(ctx, fresh)
	if err != nil || !finalPolicy.AllowInvocationHuman || finalProject != project {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	return &ExecutionPermit{marker: r.marker, binding: r.binding, resolution: final, operation: cloneOperation(operation), request: cloneRequest(request), human: human, expires: human.expires}, nil
}

func (r *Runtime) RecheckExecution(ctx context.Context, permit *ExecutionPermit, request ExecutionRequest, staged StagedMaterialReader) error {
	if r == nil || ctx == nil || staged == nil || permit == nil || permit.marker != r.marker || !permit.binding.Equal(r.binding) || !sameRequest(permit.request, request) || !r.options.Clock.Now().UTC().Before(permit.expires) {
		return diagnostic(TrustApprovalMismatch, nil)
	}
	initial, _, _, err := r.currentResolution(ctx, permit.resolution)
	if err != nil {
		return err
	}
	m, err := staged.Stage(ctx, cloneRequest(request))
	if err != nil {
		return diagnostic(TrustEvidenceMissing, err)
	}
	if !sameRequest(m.Request, request) || exactOperationFor(m.Request, m.Operation) != nil || m.Operation.ProfileBindingSHA256 != permit.operation.ProfileBindingSHA256 {
		return diagnostic(TrustApprovalMismatch, nil)
	}
	if len(m.Content) != len(m.ContentBytes) {
		return diagnostic(TrustEvidenceTampered, nil)
	}
	for i := range m.Content {
		if evidencecas.Digest(m.ContentBytes[i]) != m.Content[i].ContentSHA256 {
			return diagnostic(TrustEvidenceTampered, nil)
		}
	}
	closure, err := ComputeContentClosureSHA256(m.Content)
	if err != nil || closure != m.Request.Action.ContentClosureSHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	if evidencecas.Digest(m.ToolBytes) != m.Request.Tool.BinarySHA256 {
		return diagnostic(TrustEvidenceTampered, nil)
	}
	options, err := ComputeToolOptionsSHA256(m.ToolOptions)
	if err != nil || options != m.Request.Tool.OptionsSHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	env, err := ComputeEnvironmentPolicySHA256(m.Environment)
	if err != nil || env != m.Request.EnvironmentPolicySHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	if m.Request.OperationInputsSHA256 != permit.request.OperationInputsSHA256 {
		return diagnostic(TrustApprovalMismatch, nil)
	}
	if permit.human != nil {
		_, err = r.AuthorizeHuman(ctx, initial, m.Operation, m.Request, permit.human)
	} else {
		_, err = r.Authorize(ctx, initial, m.Operation, m.Request, permit.approval)
	}
	if err != nil {
		return err
	}
	return nil
}

func minimumPermits(project, policy string, requested bootstrap.ProfileID) bool {
	if requested == bootstrap.ProfileOrganization {
		return project == "organization" && policy == "organization"
	}
	return project == "oss" && policy == "oss"
}

type DevelopmentOptions struct {
	Objects   GitObjectReader
	Evidence  evidencecas.Reader
	Clock     bootstrap.Clock
	Inputs    bootstrap.DevelopmentInputs
	Project   ProjectContextReader
	Policy    ExternalExecutionPolicyReader
	Transport string
	Human     HumanReviewer
}
type DevelopmentRuntime struct {
	options DevelopmentOptions
	marker  *runtimeMarker
	binding bootstrap.ProfileBinding
}
type DevelopmentResolution struct {
	marker     *runtimeMarker
	snapshot   *SourceSnapshot
	binding    bootstrap.ProfileBinding
	diagnostic DevelopmentDiagnostic
}
type DevelopmentExecutionPermit struct {
	marker     *runtimeMarker
	binding    bootstrap.ProfileBinding
	resolution *DevelopmentResolution
	operation  OperationInputs
	request    ExecutionRequest
	approval   ApprovalRefs
	human      *DevelopmentHumanApproval
	expires    time.Time
}
type DevelopmentHumanApproval struct {
	marker                        *runtimeMarker
	binding                       bootstrap.ProfileBinding
	projectID, request, operation string
	expires                       time.Time
}

// DevelopmentDiagnostic is a non-forgeable, instance-bound projection. Its
// only meaning is that an explicitly development-unverified result was minted.
type DevelopmentDiagnostic struct {
	marker  *runtimeMarker
	binding bootstrap.ProfileBinding
}

func (d DevelopmentDiagnostic) ValidFor(r *DevelopmentRuntime) bool {
	return r != nil && d.marker != nil && d.marker == r.marker && d.binding.Equal(r.binding) && d.binding.ID == bootstrap.ProfileDevelopment && d.binding.Assurance == bootstrap.DevelopmentUnverified && d.binding.EvidenceClass == bootstrap.EvidenceSimulated
}

func (r *DevelopmentResolution) Diagnostic() DevelopmentDiagnostic {
	if r == nil {
		return DevelopmentDiagnostic{}
	}
	return r.diagnostic
}

func (r *DevelopmentResolution) Subject() Subject {
	if r == nil || r.snapshot == nil {
		return Subject{}
	}
	return r.snapshot.Subject()
}

func (r *DevelopmentResolution) ValidFor(runtime *DevelopmentRuntime) bool {
	return r != nil && runtime != nil && r.marker != nil && r.marker == runtime.marker && r.binding.Equal(runtime.binding) && r.diagnostic.ValidFor(runtime)
}

func NewDevelopmentRuntime(ctx context.Context, o DevelopmentOptions) (*DevelopmentRuntime, error) {
	if ctx == nil || o.Objects == nil || o.Evidence == nil || o.Clock == nil || (o.Human != nil && o.Transport != "direct-interactive-cli") {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	v, e := bootstrap.NewVerifier(o.Evidence, o.Clock, nil, 0)
	if e != nil {
		return nil, e
	}
	d, e := v.VerifyDevelopment(ctx, o.Inputs)
	if e != nil {
		return nil, diagnostic(TrustRuntimeInvalid, e)
	}
	b := d.Binding()
	return &DevelopmentRuntime{options: o, marker: &runtimeMarker{}, binding: b}, nil
}

func (r *DevelopmentRuntime) Binding() bootstrap.ProfileBinding {
	if r == nil {
		return bootstrap.ProfileBinding{}
	}
	return r.binding
}

func (r *DevelopmentRuntime) VerifySubject(ctx context.Context, s Subject) (*DevelopmentResolution, error) {
	if r == nil || ctx == nil {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	snap, e := VerifyDevelopmentSource(ctx, r.options.Objects, s)
	if e != nil {
		return nil, diagnostic(TrustSubjectInvalid, e)
	}
	d := DevelopmentDiagnostic{marker: r.marker, binding: r.binding}
	return &DevelopmentResolution{marker: r.marker, snapshot: snap, binding: r.binding, diagnostic: d}, nil
}

func (r *DevelopmentRuntime) fresh(ctx context.Context, old *DevelopmentResolution) (*DevelopmentResolution, *ExecutionPolicy, ProjectContext, error) {
	if r == nil || old == nil || !old.ValidFor(r) || r.options.Project == nil || r.options.Policy == nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, nil)
	}
	v, err := bootstrap.NewVerifier(r.options.Evidence, r.options.Clock, nil, 0)
	if err != nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, err)
	}
	d, err := v.VerifyDevelopment(ctx, r.options.Inputs)
	if err != nil || !d.Binding().Equal(r.binding) {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, err)
	}
	pc, err := r.options.Project.Load(ctx)
	if err != nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustRuntimeInvalid, err)
	}
	ps, err := r.options.Policy.Load(ctx)
	if err != nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	p, err := DecodeExecutionPolicy(ps.PolicyJSON)
	if err != nil || p.PolicySHA256 != ps.ExpectedPolicySHA256 || p.Profile != "development" || p.MinimumProfile != "development" || pc.MinimumProfile != "development" || !containsPrincipal(p, pc.SubmitterPrincipalID) {
		return nil, nil, ProjectContext{}, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	if err := validAt(p.Validity, r.options.Clock.Now().UTC()); err != nil {
		return nil, nil, ProjectContext{}, diagnostic(TrustExecutionPolicyInvalid, err)
	}
	fresh, err := r.VerifySubject(ctx, old.Subject())
	if err != nil {
		return nil, nil, ProjectContext{}, err
	}
	return fresh, p, pc, nil
}

func (r *DevelopmentRuntime) Authorize(ctx context.Context, resolution *DevelopmentResolution, operation OperationInputs, request ExecutionRequest, refs ApprovalRefs) (*DevelopmentExecutionPermit, error) {
	if r == nil {
		return nil, diagnostic(TrustRuntimeInvalid, nil)
	}
	if ctx == nil || exactOperationFor(request, operation) != nil || refs.Kind != "persistent-signed" {
		return nil, diagnostic(TrustRequestInvalid, nil)
	}
	bindingDigest, err := runtimeBindingDigest(r.binding)
	if err != nil || request.ProfileBindingSHA256 != bindingDigest {
		return nil, diagnostic(TrustRequestInvalid, err)
	}
	fresh, policy, project, err := r.fresh(ctx, resolution)
	if err != nil {
		return nil, err
	}
	if request.Provider != subjectProvider(fresh.Subject()) || request.ProjectID != project.ProjectID || request.TimeoutMillis > policy.MaxTimeoutMillis {
		return nil, diagnostic(TrustApprovalMismatch, nil)
	}
	if err = VerifyPersistentApproval(ctx, r.options.Evidence, policy, &request, request.OperationInputsSHA256, bindingDigest, r.options.Clock.Now().UTC(), refs.ApprovalCAS); err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	a, _, err := policyApprover(ctx, r.options.Evidence, policy, refs)
	if err != nil {
		return nil, err
	}
	final, finalPolicy, finalProject, err := r.fresh(ctx, fresh)
	if err != nil || finalPolicy.PolicySHA256 != policy.PolicySHA256 || finalProject != project {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	_, until, err := parseValidity(a.Validity)
	if err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	return &DevelopmentExecutionPermit{marker: r.marker, binding: r.binding, resolution: final, operation: cloneOperation(operation), request: cloneRequest(request), approval: refs, expires: until}, nil
}

func (r *DevelopmentRuntime) ReviewHuman(ctx context.Context, resolution *DevelopmentResolution, operation OperationInputs, request ExecutionRequest) (*DevelopmentHumanApproval, error) {
	if r == nil || r.options.Human == nil || r.options.Transport != "direct-interactive-cli" || exactOperationFor(request, operation) != nil {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	bindingDigest, err := runtimeBindingDigest(r.binding)
	if err != nil || request.ProfileBindingSHA256 != bindingDigest {
		return nil, diagnostic(TrustRequestInvalid, err)
	}
	fresh, policy, project, err := r.fresh(ctx, resolution)
	if err != nil || !policy.AllowInvocationHuman || request.Provider != subjectProvider(fresh.Subject()) || request.ProjectID != project.ProjectID || request.TimeoutMillis > policy.MaxTimeoutMillis {
		return nil, diagnostic(TrustApprovalRequired, err)
	}
	ok, err := r.options.Human.Review(ctx, HumanReview{request.RequestSHA256, request.OperationInputsSHA256, request.ProjectID, request.Scope})
	if err != nil || !ok {
		return nil, diagnostic(TrustApprovalRequired, err)
	}
	_, finalPolicy, finalProject, err := r.fresh(ctx, fresh)
	if err != nil || !finalPolicy.AllowInvocationHuman || finalProject != project {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	_, end, err := parseValidity(finalPolicy.Validity)
	if err != nil {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	expires := r.options.Clock.Now().UTC().Add(300 * time.Second)
	if end.Before(expires) {
		expires = end
	}
	return &DevelopmentHumanApproval{marker: r.marker, binding: r.binding, projectID: request.ProjectID, request: request.RequestSHA256, operation: request.OperationInputsSHA256, expires: expires}, nil
}

func (r *DevelopmentRuntime) AuthorizeHuman(ctx context.Context, resolution *DevelopmentResolution, operation OperationInputs, request ExecutionRequest, human *DevelopmentHumanApproval) (*DevelopmentExecutionPermit, error) {
	if r == nil || human == nil || human.marker != r.marker || !human.binding.Equal(r.binding) || human.projectID != request.ProjectID || human.request != request.RequestSHA256 || human.operation != request.OperationInputsSHA256 || !r.options.Clock.Now().UTC().Before(human.expires) || exactOperationFor(request, operation) != nil {
		return nil, diagnostic(TrustApprovalRequired, nil)
	}
	bindingDigest, digestErr := runtimeBindingDigest(r.binding)
	if digestErr != nil || request.ProfileBindingSHA256 != bindingDigest {
		return nil, diagnostic(TrustRequestInvalid, digestErr)
	}
	fresh, policy, project, err := r.fresh(ctx, resolution)
	if err != nil || !policy.AllowInvocationHuman || project.ProjectID != request.ProjectID || request.Provider != subjectProvider(fresh.Subject()) || request.TimeoutMillis > policy.MaxTimeoutMillis {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	final, finalPolicy, finalProject, err := r.fresh(ctx, fresh)
	if err != nil || !finalPolicy.AllowInvocationHuman || finalProject != project {
		return nil, diagnostic(TrustApprovalMismatch, err)
	}
	return &DevelopmentExecutionPermit{marker: r.marker, binding: r.binding, resolution: final, operation: cloneOperation(operation), request: cloneRequest(request), human: human, expires: human.expires}, nil
}

func (r *DevelopmentRuntime) RecheckExecution(ctx context.Context, permit *DevelopmentExecutionPermit, request ExecutionRequest, staged StagedMaterialReader) error {
	if r == nil || permit == nil || permit.marker != r.marker || !permit.binding.Equal(r.binding) || staged == nil || !sameRequest(permit.request, request) || !r.options.Clock.Now().UTC().Before(permit.expires) {
		return diagnostic(TrustApprovalMismatch, nil)
	}
	initial, _, _, err := r.fresh(ctx, permit.resolution)
	if err != nil {
		return err
	}
	m, err := staged.Stage(ctx, cloneRequest(request))
	if err != nil {
		return diagnostic(TrustEvidenceMissing, err)
	}
	if !sameRequest(m.Request, request) || exactOperationFor(m.Request, m.Operation) != nil {
		return diagnostic(TrustApprovalMismatch, nil)
	}
	if len(m.Content) != len(m.ContentBytes) {
		return diagnostic(TrustEvidenceTampered, nil)
	}
	for i := range m.Content {
		if evidencecas.Digest(m.ContentBytes[i]) != m.Content[i].ContentSHA256 {
			return diagnostic(TrustEvidenceTampered, nil)
		}
	}
	closure, err := ComputeContentClosureSHA256(m.Content)
	if err != nil || closure != m.Request.Action.ContentClosureSHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	if evidencecas.Digest(m.ToolBytes) != m.Request.Tool.BinarySHA256 {
		return diagnostic(TrustEvidenceTampered, nil)
	}
	o, err := ComputeToolOptionsSHA256(m.ToolOptions)
	if err != nil || o != m.Request.Tool.OptionsSHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	e, err := ComputeEnvironmentPolicySHA256(m.Environment)
	if err != nil || e != m.Request.EnvironmentPolicySHA256 {
		return diagnostic(TrustEvidenceTampered, err)
	}
	if permit.human != nil {
		_, err = r.AuthorizeHuman(ctx, initial, m.Operation, m.Request, permit.human)
	} else {
		_, err = r.Authorize(ctx, initial, m.Operation, m.Request, permit.approval)
	}
	return err
}

var (
	_ = errors.New
	_ = time.Time{}
)
