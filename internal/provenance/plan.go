package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	UpdatePlanAPIVersion            = "tplaiter.dev/update-plan/v2"
	UpdatePlanKind                  = "UpdatePlan"
	DevelopmentUpdatePlanAPIVersion = "tplaiter.dev/development-update-plan/v1"
)

var errInvalidPlan = errors.New("provenance: invalid update plan")

// UpdatePlan is a sealed, pure description. It is not an execution capability.
type UpdatePlan struct {
	APIVersion            string                   `json:"apiVersion"`
	Kind                  string                   `json:"kind"`
	TrustProfile          bootstrap.ProfileBinding `json:"trustProfile"`
	Source                PlanLockBinding          `json:"source"`
	Target                PlanLockBinding          `json:"target"`
	OperationInputsSHA256 string                   `json:"operationInputsSHA256"`
	Requests              []PlanRequest            `json:"requests"`
	PreimageSHA256        string                   `json:"preimageSHA256"`
	Actions               []PlanAction             `json:"actions"`
	Outputs               []PlanOutput             `json:"outputs"`
	CreatedAt             string                   `json:"createdAt"`
	PlanSHA256            string                   `json:"planSHA256"`
}

type PlanLockBinding struct {
	RootLockSHA256     string `json:"rootLockSHA256"`
	TemplateLockSHA256 string `json:"templateLockSHA256"`
}

// PlanRequest is output wire evidence. StablePlanInput intentionally has no
// corresponding field: only Runtime.PersistentApprovalReference may create it.
type PlanRequest struct {
	RequestSHA256 string `json:"requestSHA256"`
	GrantSHA256   string `json:"grantSHA256"`
	ApprovalCAS   string `json:"approvalCAS"`
}

type PlanAction struct {
	RequestSHA256           string               `json:"requestSHA256"`
	OperationInputsSHA256   string               `json:"operationInputsSHA256"`
	Provider                PlanProvider         `json:"provider"`
	Action                  PlanActionDefinition `json:"action"`
	Tool                    PlanTool             `json:"tool"`
	WorkingDirectoryScope   PlanWorkingDirectory `json:"workingDirectoryScope"`
	EnvironmentPolicySHA256 string               `json:"environmentPolicySHA256"`
	TimeoutMillis           int64                `json:"timeoutMillis"`
	Migration               PlanMigration        `json:"migration"`
}
type PlanProvider struct {
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	Commit         string `json:"commit"`
	TreeSHA256     string `json:"treeSHA256"`
	ContractSHA256 string `json:"contractSHA256"`
}
type PlanActionDefinition struct {
	ID                   string   `json:"id"`
	Kind                 string   `json:"kind"`
	Phase                string   `json:"phase"`
	Shell                bool     `json:"shell"`
	Argv                 []string `json:"argv"`
	ContentClosureSHA256 string   `json:"contentClosureSHA256"`
}
type PlanTool struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	BinarySHA256  string `json:"binarySHA256"`
	OptionsSHA256 string `json:"optionsSHA256"`
}
type PlanWorkingDirectory struct {
	Root string `json:"root"`
	Path string `json:"path"`
}
type PlanMigration struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
}
type PlanOutput struct {
	Path          string `json:"path"`
	ContentSHA256 string `json:"contentSHA256"`
}

type StablePlanLockInput struct {
	Resolution   *trustverify.VerifiedResolution
	Root         RootTemplateLock
	Dependencies TemplateLock
}

// StablePlanInput intentionally accepts opaque permits, not PlanRequest or
// trustverify.PersistentApprovalReference values supplied by a caller.
type StablePlanInput struct {
	Runtime               *trustverify.Runtime
	Source                StablePlanLockInput
	Target                StablePlanLockInput
	OperationInputsSHA256 string
	Permits               []*trustverify.ExecutionPermit
	PreimageSHA256        string
	Actions               []PlanAction
	Outputs               []PlanOutput
	CreatedAt             string
}

func BuildStableUpdatePlan(in StablePlanInput) (*UpdatePlan, error) {
	if in.Runtime == nil || in.Runtime.Binding().ID == bootstrap.ProfileDevelopment || !validDigest(in.OperationInputsSHA256) || !validDigest(in.PreimageSHA256) || len(in.Permits) == 0 || len(in.Permits) > 4096 || len(in.Permits) != len(in.Actions) || len(in.Outputs) > 4096 || !validCreatedAt(in.CreatedAt) {
		return nil, errInvalidPlan
	}
	binding := in.Runtime.Binding()
	if binding.Validate() != nil || validateStableLockInput(in.Runtime, binding, in.Source) != nil || validateStableLockInput(in.Runtime, binding, in.Target) != nil {
		return nil, errInvalidPlan
	}
	requests := make([]PlanRequest, len(in.Permits))
	for i, permit := range in.Permits {
		ref, err := in.Runtime.PersistentApprovalReference(permit)
		if err != nil {
			return nil, errInvalidPlan
		}
		summary := permit.Summary()
		if summary.RequestSHA256 != ref.RequestSHA256 || summary.OperationInputsSHA256 != in.OperationInputsSHA256 || validatePlanAction(in.Actions[i]) != nil || in.Actions[i].RequestSHA256 != ref.RequestSHA256 || in.Actions[i].OperationInputsSHA256 != in.OperationInputsSHA256 {
			return nil, errInvalidPlan
		}
		requests[i] = PlanRequest{RequestSHA256: ref.RequestSHA256, GrantSHA256: ref.GrantSHA256, ApprovalCAS: ref.ApprovalCAS}
	}
	for _, output := range in.Outputs {
		if !safePath(output.Path) || !validDigest(output.ContentSHA256) {
			return nil, errInvalidPlan
		}
	}
	plan := UpdatePlan{APIVersion: UpdatePlanAPIVersion, Kind: UpdatePlanKind, TrustProfile: binding, Source: planLockBinding(in.Source), Target: planLockBinding(in.Target), OperationInputsSHA256: in.OperationInputsSHA256, Requests: requests, PreimageSHA256: in.PreimageSHA256, Actions: clonePlanActions(in.Actions), Outputs: append([]PlanOutput(nil), in.Outputs...), CreatedAt: in.CreatedAt}
	digest, err := ComputeUpdatePlanSHA256(plan)
	if err != nil {
		return nil, errInvalidPlan
	}
	plan.PlanSHA256 = digest
	return &plan, nil
}

func validateStableLockInput(runtime *trustverify.Runtime, binding bootstrap.ProfileBinding, in StablePlanLockInput) error {
	if in.Resolution == nil || !in.Resolution.ValidFor(runtime, binding) || !in.Root.TrustProfile.Equal(binding) || !in.Dependencies.TrustProfile.Equal(binding) || ValidateLockPair(in.Root, in.Dependencies) != nil {
		return errInvalidPlan
	}
	s, e := in.Resolution.Subject(), in.Resolution.Evidence()
	r := in.Root.Root
	if r.Origin != s.Origin || r.TemplatePath != s.TemplatePath || r.RequestedRef != s.RequestedRef || r.Commit != s.Commit || r.TreeSHA256 != s.TreeSHA256 || r.ContractSHA256 != s.ContractSHA256 || r.StatementCAS != e.StatementCAS || r.SignatureCAS != e.SignatureCAS || r.KeyFingerprint != e.KeyFingerprint || r.CheckpointCAS != e.CheckpointCAS || r.InclusionProofCAS != e.InclusionProofCAS {
		return errInvalidPlan
	}
	return nil
}
func planLockBinding(in StablePlanLockInput) PlanLockBinding {
	return PlanLockBinding{RootLockSHA256: in.Root.RootLockSHA256, TemplateLockSHA256: in.Dependencies.LockSHA256}
}

func DecodeUpdatePlan(raw []byte) (*UpdatePlan, error) {
	if profilelessLegacyV1(raw, "tplater.dev/update-plan/v1", []string{"apiVersion", "kind", "schema", "document", "lifecycle", "mutations", "planSHA256"}, []string{"apiVersion", "kind", "schema", "createdAt", "document", "lifecycle", "mutations", "planSHA256"}) {
		return nil, ErrLegacyUnbound
	}
	if err := requireFields(raw, "apiVersion", "kind", "trustProfile", "source", "target", "operationInputsSHA256", "requests", "preimageSHA256", "actions", "outputs", "createdAt", "planSHA256"); err != nil {
		return nil, err
	}
	var p UpdatePlan
	if err := canonicaljson.DecodeStrict(raw, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p UpdatePlan) Validate() error {
	if p.APIVersion != UpdatePlanAPIVersion || p.Kind != UpdatePlanKind || p.TrustProfile.Validate() != nil || p.TrustProfile.ID == bootstrap.ProfileDevelopment || !validDigest(p.Source.RootLockSHA256) || !validDigest(p.Source.TemplateLockSHA256) || !validDigest(p.Target.RootLockSHA256) || !validDigest(p.Target.TemplateLockSHA256) || !validDigest(p.OperationInputsSHA256) || !validDigest(p.PreimageSHA256) || !validDigest(p.PlanSHA256) || len(p.Requests) == 0 || len(p.Requests) > 4096 || len(p.Actions) != len(p.Requests) || len(p.Outputs) > 4096 || !validCreatedAt(p.CreatedAt) {
		return errInvalidPlan
	}
	for i := range p.Requests {
		if !validPlanRequest(p.Requests[i]) || validatePlanAction(p.Actions[i]) != nil || p.Actions[i].RequestSHA256 != p.Requests[i].RequestSHA256 || p.Actions[i].OperationInputsSHA256 != p.OperationInputsSHA256 {
			return errInvalidPlan
		}
	}
	for _, o := range p.Outputs {
		if !safePath(o.Path) || !validDigest(o.ContentSHA256) {
			return errInvalidPlan
		}
	}
	got, err := ComputeUpdatePlanSHA256(p)
	if err != nil || got != p.PlanSHA256 {
		return errInvalidPlan
	}
	return nil
}

func ComputeUpdatePlanSHA256(p UpdatePlan) (string, error) { return updatePlanSeal(p) }
func (p UpdatePlan) ComputeSHA256() (string, error)        { return ComputeUpdatePlanSHA256(p) }
func updatePlanSeal(p UpdatePlan) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err = json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	delete(obj, "planSHA256")
	delete(obj, "createdAt")
	b, err := canonicaljson.Canonical(obj)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(UpdatePlanAPIVersion))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func validPlanRequest(v PlanRequest) bool {
	return validDigest(v.RequestSHA256) && validDigest(v.GrantSHA256) && validDigest(v.ApprovalCAS)
}
func validCreatedAt(v string) bool {
	t, err := time.Parse(time.RFC3339, v)
	return err == nil && t.UTC().Format(time.RFC3339) == v
}
func validatePlanAction(v PlanAction) error {
	if !validDigest(v.RequestSHA256) || !validDigest(v.OperationInputsSHA256) || !tokenRE.MatchString(v.Provider.Origin) || !safePath(v.Provider.TemplatePath) || !commitRE.MatchString(v.Provider.Commit) || !validDigest(v.Provider.TreeSHA256) || !validDigest(v.Provider.ContractSHA256) || !tokenRE.MatchString(v.Action.ID) || !validPlanActionKind(v.Action.Kind) || (v.Action.Phase != "before" && v.Action.Phase != "after" && v.Action.Phase != "standalone") || len(v.Action.Argv) == 0 || len(v.Action.Argv) > 256 || !validDigest(v.Action.ContentClosureSHA256) || !tokenRE.MatchString(v.Tool.ID) || !tokenRE.MatchString(v.Tool.Version) || !validDigest(v.Tool.BinarySHA256) || !validDigest(v.Tool.OptionsSHA256) || (v.WorkingDirectoryScope.Root != "project" && v.WorkingDirectoryScope.Root != "provider") || !safePath(v.WorkingDirectoryScope.Path) || !validDigest(v.EnvironmentPolicySHA256) || v.TimeoutMillis < 1 || v.TimeoutMillis > 3600000 || !validPlanMigration(v.Migration) {
		return errInvalidPlan
	}
	for _, arg := range v.Action.Argv {
		if arg == "" || len(arg) > 4096 {
			return errInvalidPlan
		}
	}
	return nil
}
func validPlanActionKind(v string) bool {
	switch v {
	case "hook", "command", "shell", "ansible", "codegen", "formatter", "tool-install", "migration":
		return true
	}
	return false
}
func validPlanMigration(v PlanMigration) bool {
	if v.Kind == "none" {
		return v.From == "" && v.To == ""
	}
	return v.Kind == "version-transition" && tokenRE.MatchString(v.From) && tokenRE.MatchString(v.To)
}
func clonePlanActions(in []PlanAction) []PlanAction {
	out := append([]PlanAction(nil), in...)
	for i := range out {
		out[i].Action.Argv = append([]string(nil), in[i].Action.Argv...)
	}
	return out
}

// DevelopmentUpdatePlan is deliberately distinct from UpdatePlan. It carries
// no persistent approvals and cannot be passed to stable sealing APIs.
type DevelopmentUpdatePlan struct {
	APIVersion   string                   `json:"apiVersion"`
	TrustProfile bootstrap.ProfileBinding `json:"trustProfile"`
	Source       trustverify.Subject      `json:"source"`
	Target       trustverify.Subject      `json:"target"`
}
type DevelopmentPlanInput struct {
	Runtime *trustverify.DevelopmentRuntime
	Source  *trustverify.DevelopmentResolution
	Target  *trustverify.DevelopmentResolution
}

func BuildDevelopmentUpdatePlan(in DevelopmentPlanInput) (*DevelopmentUpdatePlan, error) {
	if in.Runtime == nil || in.Source == nil || in.Target == nil || !in.Source.ValidFor(in.Runtime) || !in.Target.ValidFor(in.Runtime) {
		return nil, errInvalidPlan
	}
	b := in.Runtime.Binding()
	if b.ID != bootstrap.ProfileDevelopment || b.Validate() != nil {
		return nil, errInvalidPlan
	}
	return &DevelopmentUpdatePlan{APIVersion: DevelopmentUpdatePlanAPIVersion, TrustProfile: b, Source: in.Source.Subject(), Target: in.Target.Subject()}, nil
}
