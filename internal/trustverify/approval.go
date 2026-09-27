package trustverify

// This file intentionally contains wire validation and pure approval checks only.
// Runtime construction and permit minting belong to later packets.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

const (
	ExecutionPolicyAPIVersion   = "tplaiter.dev/execution-policy/v1"
	ExecutionRequestAPIVersion  = "tplaiter.dev/execution-request/v1"
	ExecutionApprovalAPIVersion = "tplaiter.dev/execution-approval/v1"
	maxApprovalJSON             = 1 << 20
)

type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}
type Principal struct {
	ID string `json:"id"`
}
type IssuerPrincipal struct {
	Issuer      string `json:"issuer"`
	PrincipalID string `json:"principalID"`
}
type SourceRule struct {
	PolicyOrigin string `json:"policyOrigin"`
	Issuer       string `json:"issuer"`
	Origin       string `json:"origin"`
	TemplatePath string `json:"templatePath"`
	Predicate    string `json:"predicate"`
	Format       string `json:"format"`
}
type ApprovalScope struct {
	ProjectID      string `json:"projectID"`
	OperationScope string `json:"operationScope"`
	ActionKind     string `json:"actionKind"`
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
}
type Approver struct {
	ID              string          `json:"id"`
	PrincipalID     string          `json:"principalID"`
	IdentityClass   string          `json:"identityClass"`
	KeyFingerprint  string          `json:"keyFingerprint"`
	PublicKeyBase64 string          `json:"publicKeyBase64"`
	Validity        Validity        `json:"validity"`
	Scopes          []ApprovalScope `json:"scopes"`
}
type ExecutionPolicy struct {
	APIVersion           string            `json:"apiVersion"`
	PolicyID             string            `json:"policyId"`
	Profile              string            `json:"profile"`
	MinimumProfile       string            `json:"minimumProfile"`
	Validity             Validity          `json:"validity"`
	Principals           []Principal       `json:"principals"`
	IssuerPrincipals     []IssuerPrincipal `json:"issuerPrincipals"`
	SourceRules          []SourceRule      `json:"sourceRules"`
	Approvers            []Approver        `json:"approvers"`
	AllowInvocationHuman bool              `json:"allowInvocationHuman"`
	MaxTimeoutMillis     int64             `json:"maxTimeoutMillis"`
	PolicySHA256         string            `json:"policySHA256"`
}

type Provider struct {
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	Commit         string `json:"commit"`
	TreeSHA256     string `json:"treeSHA256"`
	ContractSHA256 string `json:"contractSHA256"`
}
type Action struct {
	ID                   string   `json:"id"`
	Kind                 string   `json:"kind"`
	Phase                string   `json:"phase"`
	Shell                bool     `json:"shell"`
	Argv                 []string `json:"argv"`
	ContentClosureSHA256 string   `json:"contentClosureSHA256"`
}
type Tool struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	BinarySHA256  string `json:"binarySHA256"`
	OptionsSHA256 string `json:"optionsSHA256"`
}
type WorkingDirectoryScope struct {
	Root string `json:"root"`
	Path string `json:"path"`
}
type Migration struct {
	Kind string `json:"kind"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}
type ExecutionRequest struct {
	APIVersion              string                `json:"apiVersion"`
	ProfileBindingSHA256    string                `json:"profileBindingSHA256"`
	OperationInputsSHA256   string                `json:"operationInputsSHA256"`
	ProjectID               string                `json:"projectID"`
	Scope                   string                `json:"scope"`
	Provider                Provider              `json:"provider"`
	Action                  Action                `json:"action"`
	Tool                    Tool                  `json:"tool"`
	WorkingDirectoryScope   WorkingDirectoryScope `json:"workingDirectoryScope"`
	EnvironmentPolicySHA256 string                `json:"environmentPolicySHA256"`
	TimeoutMillis           int64                 `json:"timeoutMillis"`
	Migration               Migration             `json:"migration"`
	RequestSHA256           string                `json:"requestSHA256"`
}
type ExecutionApproval struct {
	APIVersion            string   `json:"apiVersion"`
	Kind                  string   `json:"kind"`
	RequestSHA256         string   `json:"requestSHA256"`
	ProfileBindingSHA256  string   `json:"profileBindingSHA256"`
	OperationInputsSHA256 string   `json:"operationInputsSHA256"`
	ProjectID             string   `json:"projectID"`
	Scope                 string   `json:"scope"`
	ApproverID            string   `json:"approverID"`
	IdentityClass         string   `json:"identityClass"`
	ExecutionPolicySHA256 string   `json:"executionPolicySHA256"`
	Validity              Validity `json:"validity"`
	KeyFingerprint        string   `json:"keyFingerprint"`
	GrantSHA256           string   `json:"grantSHA256"`
	SignatureCAS          string   `json:"signatureCAS"`
}
type ContentEntry struct {
	Root          string `json:"root"`
	Path          string `json:"path"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"contentSHA256"`
}
type EnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type EnvironmentPolicy struct {
	APIVersion   string                `json:"apiVersion"`
	Inherit      bool                  `json:"inherit"`
	Variables    []EnvironmentVariable `json:"variables"`
	Capabilities []string              `json:"capabilities"`
}
type ActionMaterial struct {
	Provider                Provider              `json:"provider"`
	Action                  Action                `json:"action"`
	Tool                    Tool                  `json:"tool"`
	WorkingDirectoryScope   WorkingDirectoryScope `json:"workingDirectoryScope"`
	EnvironmentPolicySHA256 string                `json:"environmentPolicySHA256"`
	TimeoutMillis           int64                 `json:"timeoutMillis"`
	Migration               Migration             `json:"migration"`
}
type OperationInputs struct {
	APIVersion           string           `json:"apiVersion"`
	ProfileBindingSHA256 string           `json:"profileBindingSHA256"`
	ProjectID            string           `json:"projectID"`
	Scope                string           `json:"scope"`
	PreimageSHA256       string           `json:"preimageSHA256"`
	AnswersSHA256        string           `json:"answersSHA256"`
	Subjects             []Provider       `json:"subjects"`
	Actions              []ActionMaterial `json:"actions"`
}

// ApprovalRefs deliberately has no human branch: human approval is an
// invocation-local opaque capability and cannot be reconstructed from data.
type ApprovalRefs struct {
	Kind        string
	ApprovalCAS string
}

// HumanReview is the complete immutable identity shown by a trusted direct
// interactive CLI adapter. It contains no callback-selected authority.
type HumanReview struct {
	RequestSHA256         string
	OperationInputsSHA256 string
	ProjectID             string
	Scope                 string
}

type HumanReviewer interface {
	Review(context.Context, HumanReview) (bool, error)
}

// StagedMaterial is returned by a composition-owned reader immediately before
// execution. The raw bytes are used only to recompute the already-declared
// digests; this package never opens a path or starts a process.
type StagedMaterial struct {
	Operation    OperationInputs
	Request      ExecutionRequest
	Content      []ContentEntry
	ContentBytes [][]byte
	ToolBytes    []byte
	ToolOptions  []string
	Environment  EnvironmentPolicy
}

type StagedMaterialReader interface {
	Stage(context.Context, ExecutionRequest) (StagedMaterial, error)
}

var principalRE = regexp.MustCompile(`^principal:[a-z0-9][a-z0-9._-]{0,127}$`)
var policyKeyRE = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var envRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func DecodeExecutionPolicy(raw []byte) (*ExecutionPolicy, error) {
	if err := strictObject(raw, []string{"apiVersion", "policyId", "profile", "minimumProfile", "validity", "principals", "issuerPrincipals", "sourceRules", "approvers", "allowInvocationHuman", "maxTimeoutMillis", "policySHA256"}); err != nil {
		return nil, policyErr(err)
	}
	if err := policyWirePresence(raw); err != nil {
		return nil, policyErr(err)
	}
	var p ExecutionPolicy
	if err := canonicaljson.DecodeStrict(raw, &p); err != nil {
		return nil, policyErr(err)
	}
	if err := validatePolicy(&p); err != nil {
		return nil, policyErr(err)
	}
	return &p, nil
}
func DecodeExecutionRequest(raw []byte) (*ExecutionRequest, error) {
	if err := strictObject(raw, []string{"apiVersion", "profileBindingSHA256", "operationInputsSHA256", "projectID", "scope", "provider", "action", "tool", "workingDirectoryScope", "environmentPolicySHA256", "timeoutMillis", "migration", "requestSHA256"}); err != nil {
		return nil, requestErr(err)
	}
	if err := requestWirePresence(raw); err != nil {
		return nil, requestErr(err)
	}
	var r ExecutionRequest
	if err := canonicaljson.DecodeStrict(raw, &r); err != nil {
		return nil, requestErr(err)
	}
	if err := validateRequest(&r); err != nil {
		return nil, requestErr(err)
	}
	return &r, nil
}
func DecodeExecutionApproval(raw []byte) (*ExecutionApproval, error) {
	if err := strictObject(raw, []string{"apiVersion", "kind", "requestSHA256", "profileBindingSHA256", "operationInputsSHA256", "projectID", "scope", "approverID", "identityClass", "executionPolicySHA256", "validity", "keyFingerprint", "grantSHA256", "signatureCAS"}); err != nil {
		return nil, approvalErr(err)
	}
	if err := approvalWirePresence(raw); err != nil {
		return nil, approvalErr(err)
	}
	var a ExecutionApproval
	if err := canonicaljson.DecodeStrict(raw, &a); err != nil {
		return nil, approvalErr(err)
	}
	if err := validateApproval(&a); err != nil {
		return nil, approvalErr(err)
	}
	return &a, nil
}

func (p ExecutionPolicy) ComputePolicySHA256() (string, error) {
	p.PolicySHA256 = ""
	if err := validatePolicyBody(&p); err != nil {
		return "", err
	}
	return approvalDigest(ExecutionPolicyAPIVersion, policyDigestWire(p))
}
func (p ExecutionPolicy) VerifyPolicySHA256() error {
	d, e := p.ComputePolicySHA256()
	if e != nil || d != p.PolicySHA256 {
		return errors.New("trustverify: policy digest mismatch")
	}
	return nil
}
func (r ExecutionRequest) ComputeRequestSHA256() (string, error) {
	r.RequestSHA256 = ""
	if err := validateRequestBody(&r); err != nil {
		return "", err
	}
	return approvalDigest(ExecutionRequestAPIVersion, requestDigestWire(r))
}
func (r ExecutionRequest) VerifyRequestSHA256() error {
	d, e := r.ComputeRequestSHA256()
	if e != nil || d != r.RequestSHA256 {
		return errors.New("trustverify: request digest mismatch")
	}
	return nil
}
func (a ExecutionApproval) ComputeGrantSHA256() (string, error) {
	a.GrantSHA256 = ""
	a.SignatureCAS = ""
	if err := validateApprovalBody(&a); err != nil {
		return "", err
	}
	return approvalDigest(ExecutionApprovalAPIVersion, approvalDigestWire(a))
}
func (a ExecutionApproval) VerifyGrantSHA256() error {
	d, e := a.ComputeGrantSHA256()
	if e != nil || d != a.GrantSHA256 {
		return errors.New("trustverify: grant digest mismatch")
	}
	return nil
}

func ComputeContentClosureSHA256(entries []ContentEntry) (string, error) {
	if len(entries) > 4096 {
		return "", errors.New("trustverify: content entry limit")
	}
	last := ""
	for _, e := range entries {
		k := e.Root + "\x00" + e.Path
		if (e.Root != "project" && e.Root != "provider") || !safePath(e.Path) || (e.Mode != "100644" && e.Mode != "100755") || !validDigest(e.ContentSHA256) || k <= last {
			return "", errors.New("trustverify: invalid content closure")
		}
		last = k
	}
	return approvalDigest("tplaiter.dev/execution-content/v1", struct {
		APIVersion string         `json:"apiVersion"`
		Entries    []ContentEntry `json:"entries"`
	}{"tplaiter.dev/execution-content/v1", entries})
}
func ComputeToolOptionsSHA256(options []string) (string, error) {
	if len(options) > 256 {
		return "", errors.New("trustverify: options limit")
	}
	for _, x := range options {
		if !utf8.ValidString(x) || strings.ContainsRune(x, 0) || len(x) > 4096 || utf8.RuneCountInString(x) > 4096 {
			return "", errors.New("trustverify: invalid option")
		}
	}
	return approvalDigest("tplaiter.dev/tool-options/v1", struct {
		APIVersion string   `json:"apiVersion"`
		Options    []string `json:"options"`
	}{"tplaiter.dev/tool-options/v1", options})
}
func ComputeEnvironmentPolicySHA256(e EnvironmentPolicy) (string, error) {
	if e.APIVersion != "tplaiter.dev/execution-environment/v1" || e.Inherit || len(e.Variables) > 1024 || len(e.Capabilities) != 0 {
		return "", errors.New("trustverify: invalid environment policy")
	}
	last := ""
	for _, v := range e.Variables {
		if !envRE.MatchString(v.Name) || v.Name <= last || !utf8.ValidString(v.Value) || strings.ContainsRune(v.Value, 0) || len(v.Value) > 4096 {
			return "", errors.New("trustverify: invalid environment variable")
		}
		last = v.Name
	}
	return approvalDigest(e.APIVersion, e)
}
func ComputeOperationInputsSHA256(o OperationInputs) (string, error) {
	if o.APIVersion != "tplaiter.dev/operation-inputs/v1" || !validDigest(o.ProfileBindingSHA256) || !token(o.ProjectID) || !scope(o.Scope) || !validDigest(o.PreimageSHA256) || !validDigest(o.AnswersSHA256) || len(o.Subjects) > 1024 || len(o.Actions) > 4096 {
		return "", errors.New("trustverify: invalid operation inputs")
	}
	last := ""
	for _, p := range o.Subjects {
		k := p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit
		if !provider(p) || k <= last {
			return "", errors.New("trustverify: invalid operation subject")
		}
		last = k
	}
	for _, a := range o.Actions {
		if !provider(a.Provider) || !action(a.Action) || !tool(a.Tool) || !cwd(a.WorkingDirectoryScope) || !validDigest(a.EnvironmentPolicySHA256) || a.TimeoutMillis < 1 || a.TimeoutMillis > 3600000 || !migration(a.Migration) {
			return "", errors.New("trustverify: invalid operation action")
		}
	}
	return approvalDigest(o.APIVersion, o)
}

// VerifyPersistentApproval is intentionally a pure verifier. It returns no permit
// or authority capability; callers must still bind its result in T3-D.
func VerifyPersistentApproval(ctx context.Context, store evidencecas.Reader, policy *ExecutionPolicy, request *ExecutionRequest, operationSHA256, profileBindingSHA256 string, now time.Time, approvalCAS string) error {
	if ctx == nil || store == nil || policy == nil || request == nil || !validDigest(approvalCAS) || !validDigest(operationSHA256) || !validDigest(profileBindingSHA256) {
		return errors.New("trustverify: approval inputs invalid")
	}
	if err := validatePolicy(policy); err != nil {
		return errors.New("trustverify: policy invalid")
	}
	if err := validateRequest(request); err != nil {
		return errors.New("trustverify: request invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := store.Read(ctx, approvalCAS)
	if err != nil {
		return errors.New("trustverify: approval unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(raw) > maxApprovalJSON || evidencecas.Digest(raw) != approvalCAS {
		return errors.New("trustverify: approval evidence invalid")
	}
	a, err := DecodeExecutionApproval(raw)
	if err != nil {
		return err
	}
	if err = a.VerifyGrantSHA256(); err != nil {
		return err
	}
	if a.RequestSHA256 != request.RequestSHA256 || a.ProfileBindingSHA256 != profileBindingSHA256 || a.OperationInputsSHA256 != operationSHA256 || a.ProjectID != request.ProjectID || a.Scope != request.Scope || a.ExecutionPolicySHA256 != policy.PolicySHA256 {
		return errors.New("trustverify: approval binding mismatch")
	}
	if err := validAt(a.Validity, now); err != nil {
		return errors.New("trustverify: approval expired")
	}
	var found *Approver
	for i := range policy.Approvers {
		q := &policy.Approvers[i]
		if q.ID == a.ApproverID && q.KeyFingerprint == a.KeyFingerprint {
			found = q
			break
		}
	}
	if found == nil || found.IdentityClass != a.IdentityClass || validAt(found.Validity, now) != nil {
		return errors.New("trustverify: approver unavailable")
	}
	key, err := decodeExecutionPolicyPublicKey(found.PublicKeyBase64)
	if err != nil || bootstrap.Fingerprint(key) != found.KeyFingerprint {
		return errors.New("trustverify: approver key invalid")
	}
	sigRaw, err := store.Read(ctx, a.SignatureCAS)
	if err != nil {
		return errors.New("trustverify: signature unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(sigRaw) > 1024 || evidencecas.Digest(sigRaw) != a.SignatureCAS {
		return errors.New("trustverify: signature evidence invalid")
	}
	sig, err := bootstrap.DecodeSignature(sigRaw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("trustverify: signature invalid")
	}
	msg, err := digestBytes(a.GrantSHA256)
	if err != nil || !ed25519.Verify(key, msg, sig) {
		return errors.New("trustverify: approval signature invalid")
	}
	if !hasScope(*found, request) {
		return errors.New("trustverify: approval scope denied")
	}
	return nil
}

func validatePolicy(p *ExecutionPolicy) error {
	if err := validatePolicyBody(p); err != nil {
		return err
	}
	return p.VerifyPolicySHA256()
}
func validatePolicyBody(p *ExecutionPolicy) error {
	if p == nil || p.APIVersion != ExecutionPolicyAPIVersion || !token(p.PolicyID) || !profile(p.Profile) || !profile(p.MinimumProfile) || p.MaxTimeoutMillis < 1 || p.MaxTimeoutMillis > 3600000 {
		return errors.New("invalid policy")
	}
	if _, _, e := parseValidity(p.Validity); e != nil {
		return e
	}
	if len(p.Principals) < 1 || len(p.Principals) > 1024 || len(p.IssuerPrincipals) < 1 || len(p.IssuerPrincipals) > 1024 || len(p.SourceRules) < 1 || len(p.SourceRules) > 1024 || len(p.Approvers) > 64 {
		return errors.New("policy cardinality")
	}
	principals := map[string]bool{}
	prev := ""
	for _, x := range p.Principals {
		if !principalRE.MatchString(x.ID) || x.ID <= prev || principals[x.ID] {
			return errors.New("principal ordering")
		}
		principals[x.ID] = true
		prev = x.ID
	}
	prev = ""
	issuers := map[string]bool{}
	for _, x := range p.IssuerPrincipals {
		if !token(x.Issuer) || !principals[x.PrincipalID] || x.Issuer <= prev || issuers[x.Issuer] {
			return errors.New("issuer mapping")
		}
		issuers[x.Issuer] = true
		prev = x.Issuer
	}
	prev = ""
	seenRules := map[string]bool{}
	for _, x := range p.SourceRules {
		k := x.PolicyOrigin + "\x00" + x.Issuer + "\x00" + x.Origin + "\x00" + x.TemplatePath + "\x00" + x.Predicate
		if !token(x.PolicyOrigin) || !token(x.Issuer) || !token(x.Origin) || !safePath(x.TemplatePath) || !token(x.Predicate) || x.Format != "tplaiter-publisher-statement-v1" || !issuers[x.Issuer] || k < prev || seenRules[k] {
			return errors.New("source rule")
		}
		seenRules[k] = true
		prev = k
	}
	prev = ""
	ids := map[string]bool{}
	fps := map[string]bool{}
	for i := range p.Approvers {
		x := &p.Approvers[i]
		if !token(x.ID) || !principals[x.PrincipalID] || !identityClass(x.IdentityClass) || !validDigest(x.KeyFingerprint) || ids[x.ID] || fps[x.KeyFingerprint] || x.ID <= prev {
			return errors.New("approver")
		}
		key, e := decodeExecutionPolicyPublicKey(x.PublicKeyBase64)
		if e != nil || bootstrap.Fingerprint(key) != x.KeyFingerprint {
			return errors.New("approver key")
		}
		if _, _, e = parseValidity(x.Validity); e != nil {
			return e
		}
		if len(x.Scopes) < 1 || len(x.Scopes) > 1024 {
			return errors.New("scope cardinality")
		}
		last := ""
		ss := map[string]bool{}
		for _, s := range x.Scopes {
			k := s.ProjectID + "\x00" + s.OperationScope + "\x00" + s.ActionKind + "\x00" + s.Origin + "\x00" + s.TemplatePath
			if !token(s.ProjectID) || !scope(s.OperationScope) || !actionKind(s.ActionKind) || !token(s.Origin) || !safePath(s.TemplatePath) || k <= last || ss[k] {
				return errors.New("scope")
			}
			last = k
			ss[k] = true
		}
		ids[x.ID] = true
		fps[x.KeyFingerprint] = true
		prev = x.ID
	}
	return nil
}
func validateRequest(r *ExecutionRequest) error {
	if err := validateRequestBody(r); err != nil {
		return err
	}
	return r.VerifyRequestSHA256()
}
func validateRequestBody(r *ExecutionRequest) error {
	if r == nil || r.APIVersion != ExecutionRequestAPIVersion || !validDigest(r.ProfileBindingSHA256) || !validDigest(r.OperationInputsSHA256) || !token(r.ProjectID) || !scope(r.Scope) || !provider(r.Provider) || !action(r.Action) || !tool(r.Tool) || r.Action.Argv[0] != r.Tool.ID || !cwd(r.WorkingDirectoryScope) || !validDigest(r.EnvironmentPolicySHA256) || r.TimeoutMillis < 1 || r.TimeoutMillis > 3600000 || !migration(r.Migration) {
		return errors.New("invalid request")
	}
	if r.Action.Kind == "migration" {
		if r.Migration.Kind != "version-transition" || (r.Scope != "new" && r.Scope != "update" && r.Scope != "migration") {
			return errors.New("invalid migration request")
		}
	} else if r.Migration.Kind != "none" {
		return errors.New("invalid migration request")
	}
	return nil
}
func validateApproval(a *ExecutionApproval) error {
	if err := validateApprovalBody(a); err != nil {
		return err
	}
	return a.VerifyGrantSHA256()
}
func validateApprovalBody(a *ExecutionApproval) error {
	if a == nil || a.APIVersion != ExecutionApprovalAPIVersion || a.Kind != "persistent-signed" || !validDigest(a.RequestSHA256) || !validDigest(a.ProfileBindingSHA256) || !validDigest(a.OperationInputsSHA256) || !token(a.ProjectID) || !scope(a.Scope) || !token(a.ApproverID) || !identityClass(a.IdentityClass) || !validDigest(a.ExecutionPolicySHA256) || !validDigest(a.KeyFingerprint) {
		return errors.New("invalid approval")
	}
	_, _, e := parseValidity(a.Validity)
	return e
}

func strictObject(raw []byte, fields []string) error {
	if len(raw) == 0 || len(raw) > maxApprovalJSON || !utf8.Valid(raw) {
		return errors.New("invalid JSON size or UTF-8")
	}
	var m map[string]json.RawMessage
	if e := canonicaljson.DecodeStrict(raw, &m); e != nil {
		return e
	}
	if len(m) != len(fields) {
		return errors.New("unknown or missing field")
	}
	for _, k := range fields {
		v, ok := m[k]
		if !ok || string(v) == "null" {
			return errors.New("missing or null field")
		}
	}
	return nil
}
func objectFields(raw []byte, fields []string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if e := json.Unmarshal(raw, &m); e != nil {
		return nil, e
	}
	for _, k := range fields {
		v, ok := m[k]
		if !ok || string(v) == "null" {
			return nil, errors.New("missing nested field")
		}
	}
	return m, nil
}
func arrayFields(raw json.RawMessage, fields []string) error {
	var a []json.RawMessage
	if e := json.Unmarshal(raw, &a); e != nil {
		return e
	}
	for _, x := range a {
		if _, e := objectFields(x, fields); e != nil {
			return e
		}
	}
	return nil
}
func policyWirePresence(raw []byte) error {
	m, e := objectFields(raw, []string{"validity", "principals", "issuerPrincipals", "sourceRules", "approvers"})
	if e != nil {
		return e
	}
	if _, e = objectFields(m["validity"], []string{"notBefore", "notAfter"}); e != nil {
		return e
	}
	if e = arrayFields(m["principals"], []string{"id"}); e != nil {
		return e
	}
	if e = arrayFields(m["issuerPrincipals"], []string{"issuer", "principalID"}); e != nil {
		return e
	}
	if e = arrayFields(m["sourceRules"], []string{"policyOrigin", "issuer", "origin", "templatePath", "predicate", "format"}); e != nil {
		return e
	}
	var a []json.RawMessage
	if e = json.Unmarshal(m["approvers"], &a); e != nil {
		return e
	}
	for _, x := range a {
		q, e := objectFields(x, []string{"id", "principalID", "identityClass", "keyFingerprint", "publicKeyBase64", "validity", "scopes"})
		if e != nil {
			return e
		}
		if _, e = objectFields(q["validity"], []string{"notBefore", "notAfter"}); e != nil {
			return e
		}
		if e = arrayFields(q["scopes"], []string{"projectID", "operationScope", "actionKind", "origin", "templatePath"}); e != nil {
			return e
		}
	}
	return nil
}
func requestWirePresence(raw []byte) error {
	m, e := objectFields(raw, []string{"provider", "action", "tool", "workingDirectoryScope", "migration"})
	if e != nil {
		return e
	}
	for _, x := range []struct {
		r json.RawMessage
		f []string
	}{{m["provider"], []string{"origin", "templatePath", "commit", "treeSHA256", "contractSHA256"}}, {m["action"], []string{"id", "kind", "phase", "shell", "argv", "contentClosureSHA256"}}, {m["tool"], []string{"id", "version", "binarySHA256", "optionsSHA256"}}, {m["workingDirectoryScope"], []string{"root", "path"}}, {m["migration"], []string{"kind"}}} {
		if _, e = objectFields(x.r, x.f); e != nil {
			return e
		}
	}
	var migration map[string]json.RawMessage
	if e = json.Unmarshal(m["migration"], &migration); e != nil {
		return e
	}
	kind, ok := migration["kind"]
	if !ok {
		return errors.New("missing migration kind")
	}
	var k string
	if e = json.Unmarshal(kind, &k); e != nil {
		return e
	}
	if k == "none" {
		if len(migration) != 1 {
			return errors.New("none migration has members")
		}
	} else if k == "version-transition" {
		if len(migration) != 3 || migration["from"] == nil || migration["to"] == nil || string(migration["from"]) == "null" || string(migration["to"]) == "null" {
			return errors.New("transition migration fields")
		}
	} else {
		return errors.New("invalid migration kind")
	}
	return nil
}
func approvalWirePresence(raw []byte) error {
	m, e := objectFields(raw, []string{"validity"})
	if e != nil {
		return e
	}
	_, e = objectFields(m["validity"], []string{"notBefore", "notAfter"})
	return e
}
func approvalDigest(domain string, v any) (string, error) {
	b, e := canonicaljson.Canonical(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append(append([]byte(domain), 0), b...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
func policyDigestWire(p ExecutionPolicy) any {
	return struct {
		APIVersion           string            `json:"apiVersion"`
		PolicyID             string            `json:"policyId"`
		Profile              string            `json:"profile"`
		MinimumProfile       string            `json:"minimumProfile"`
		Validity             Validity          `json:"validity"`
		Principals           []Principal       `json:"principals"`
		IssuerPrincipals     []IssuerPrincipal `json:"issuerPrincipals"`
		SourceRules          []SourceRule      `json:"sourceRules"`
		Approvers            []Approver        `json:"approvers"`
		AllowInvocationHuman bool              `json:"allowInvocationHuman"`
		MaxTimeoutMillis     int64             `json:"maxTimeoutMillis"`
	}{p.APIVersion, p.PolicyID, p.Profile, p.MinimumProfile, p.Validity, p.Principals, p.IssuerPrincipals, p.SourceRules, p.Approvers, p.AllowInvocationHuman, p.MaxTimeoutMillis}
}
func requestDigestWire(r ExecutionRequest) any {
	return struct {
		APIVersion              string                `json:"apiVersion"`
		ProfileBindingSHA256    string                `json:"profileBindingSHA256"`
		OperationInputsSHA256   string                `json:"operationInputsSHA256"`
		ProjectID               string                `json:"projectID"`
		Scope                   string                `json:"scope"`
		Provider                Provider              `json:"provider"`
		Action                  Action                `json:"action"`
		Tool                    Tool                  `json:"tool"`
		WorkingDirectoryScope   WorkingDirectoryScope `json:"workingDirectoryScope"`
		EnvironmentPolicySHA256 string                `json:"environmentPolicySHA256"`
		TimeoutMillis           int64                 `json:"timeoutMillis"`
		Migration               Migration             `json:"migration"`
	}{r.APIVersion, r.ProfileBindingSHA256, r.OperationInputsSHA256, r.ProjectID, r.Scope, r.Provider, r.Action, r.Tool, r.WorkingDirectoryScope, r.EnvironmentPolicySHA256, r.TimeoutMillis, r.Migration}
}
func approvalDigestWire(a ExecutionApproval) any {
	return struct {
		APIVersion            string   `json:"apiVersion"`
		Kind                  string   `json:"kind"`
		RequestSHA256         string   `json:"requestSHA256"`
		ProfileBindingSHA256  string   `json:"profileBindingSHA256"`
		OperationInputsSHA256 string   `json:"operationInputsSHA256"`
		ProjectID             string   `json:"projectID"`
		Scope                 string   `json:"scope"`
		ApproverID            string   `json:"approverID"`
		IdentityClass         string   `json:"identityClass"`
		ExecutionPolicySHA256 string   `json:"executionPolicySHA256"`
		Validity              Validity `json:"validity"`
		KeyFingerprint        string   `json:"keyFingerprint"`
	}{a.APIVersion, a.Kind, a.RequestSHA256, a.ProfileBindingSHA256, a.OperationInputsSHA256, a.ProjectID, a.Scope, a.ApproverID, a.IdentityClass, a.ExecutionPolicySHA256, a.Validity, a.KeyFingerprint}
}

func decodeExecutionPolicyPublicKey(s string) (ed25519.PublicKey, error) {
	if len(s) != 44 || !policyKeyRE.MatchString(s) {
		return nil, errors.New("trustverify: invalid execution policy key")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("trustverify: invalid execution policy key")
	}
	return ed25519.PublicKey(b), nil
}
func parseValidity(v Validity) (time.Time, time.Time, error) {
	a, e := time.Parse(time.RFC3339, v.NotBefore)
	if e != nil || a.UTC().Format(time.RFC3339) != v.NotBefore {
		return time.Time{}, time.Time{}, errors.New("invalid validity")
	}
	b, e := time.Parse(time.RFC3339, v.NotAfter)
	if e != nil || b.UTC().Format(time.RFC3339) != v.NotAfter || !a.Before(b) {
		return time.Time{}, time.Time{}, errors.New("invalid validity")
	}
	return a, b, nil
}
func validAt(v Validity, n time.Time) error {
	a, b, e := parseValidity(v)
	if e != nil || n.Before(a) || !n.Before(b) {
		return errors.New("outside validity")
	}
	return nil
}
func validDigest(s string) bool { return digestRE.MatchString(s) }
func digestBytes(s string) ([]byte, error) {
	if !validDigest(s) {
		return nil, errors.New("invalid digest")
	}
	return hex.DecodeString(s[7:])
}
func token(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func safePath(s string) bool {
	if s == "." {
		return true
	}
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 1024 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.ContainsAny(s, `\\:`) {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, r := range p {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}
func profile(s string) bool       { return s == "oss" || s == "organization" || s == "development" }
func identityClass(s string) bool { return s == "operator" || s == "automation" }
func scope(s string) bool {
	switch s {
	case "new", "update", "run", "gen", "tool-install", "migration":
		return true
	}
	return false
}
func actionKind(s string) bool {
	switch s {
	case "hook", "command", "shell", "ansible", "codegen", "formatter", "tool-install", "migration":
		return true
	}
	return false
}
func provider(p Provider) bool {
	return token(p.Origin) && safePath(p.TemplatePath) && commitRE.MatchString(p.Commit) && validDigest(p.TreeSHA256) && validDigest(p.ContractSHA256)
}
func action(a Action) bool {
	if !token(a.ID) || !actionKind(a.Kind) || (a.Phase != "before" && a.Phase != "after" && a.Phase != "standalone") || !validDigest(a.ContentClosureSHA256) || len(a.Argv) < 1 || len(a.Argv) > 256 || a.Argv[0] == "" {
		return false
	}
	if (a.Kind == "shell" && !a.Shell) || (a.Shell && a.Kind != "shell" && a.Kind != "hook" && a.Kind != "migration") {
		return false
	}
	var total int
	for _, x := range a.Argv {
		if !utf8.ValidString(x) || strings.ContainsRune(x, 0) || len(x) > 4096 || utf8.RuneCountInString(x) > 4096 {
			return false
		}
		total += len(x)
	}
	return total <= 64<<10
}
func tool(t Tool) bool {
	return token(t.ID) && token(t.Version) && validDigest(t.BinarySHA256) && validDigest(t.OptionsSHA256)
}
func cwd(c WorkingDirectoryScope) bool {
	return (c.Root == "project" || c.Root == "provider") && safePath(c.Path)
}
func migration(m Migration) bool {
	if m.Kind == "none" {
		return m.From == "" && m.To == ""
	}
	return m.Kind == "version-transition" && token(m.From) && token(m.To) && m.From != m.To
}
func hasScope(a Approver, r *ExecutionRequest) bool {
	for _, s := range a.Scopes {
		if s.ProjectID == r.ProjectID && s.OperationScope == r.Scope && s.ActionKind == r.Action.Kind && s.Origin == r.Provider.Origin && s.TemplatePath == r.Provider.TemplatePath {
			return true
		}
	}
	return false
}
func policyErr(e error) error   { return fmt.Errorf("trustverify: execution policy invalid: %w", e) }
func requestErr(e error) error  { return fmt.Errorf("trustverify: execution request invalid: %w", e) }
func approvalErr(e error) error { return fmt.Errorf("trustverify: execution approval invalid: %w", e) }

// Keep sort imported as an explicit compile-time guard that callers cannot rely
// on map iteration for policy ordering; validation above compares wire ordering.
var _ = sort.Strings
var _ = envRE
