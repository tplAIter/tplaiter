package provenance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	js "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func planFixture(t *testing.T) UpdatePlan {
	t.Helper()
	root := fixtureRoot()
	deps := TemplateLock{APIVersion: TemplateLockAPIVersion, Kind: DependencyExportLockKind, TrustProfile: root.TrustProfile, RootLockSHA256: root.RootLockSHA256, Dependencies: []DependencySubject{}}
	deps.LockSHA256, _ = ComputeTemplateLockSHA256(deps)
	request := d('8')
	p := UpdatePlan{
		APIVersion: UpdatePlanAPIVersion, Kind: UpdatePlanKind, TrustProfile: root.TrustProfile,
		Source: PlanLockBinding{RootLockSHA256: root.RootLockSHA256, TemplateLockSHA256: deps.LockSHA256}, Target: PlanLockBinding{RootLockSHA256: root.RootLockSHA256, TemplateLockSHA256: deps.LockSHA256},
		OperationInputsSHA256: d('9'), PreimageSHA256: d('a'), CreatedAt: "2026-06-01T00:00:00Z",
		Requests: []PlanRequest{{RequestSHA256: request, GrantSHA256: d('b'), ApprovalCAS: d('c')}},
		Actions:  []PlanAction{{RequestSHA256: request, OperationInputsSHA256: d('9'), Provider: PlanProvider{Origin: "https://example.test/source", TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: d('1'), ContractSHA256: d('2')}, Action: PlanActionDefinition{ID: "action.test", Kind: "command", Phase: "standalone", Argv: []string{"tool.test", "--exact"}, ContentClosureSHA256: d('3')}, Tool: PlanTool{ID: "tool.test", Version: "v1", BinarySHA256: d('4'), OptionsSHA256: d('5')}, WorkingDirectoryScope: PlanWorkingDirectory{Root: "project", Path: "."}, EnvironmentPolicySHA256: d('6'), TimeoutMillis: 100, Migration: PlanMigration{Kind: "none"}}},
		Outputs:  []PlanOutput{{Path: "generated.txt", ContentSHA256: d('7')}},
	}
	p.PlanSHA256, _ = ComputeUpdatePlanSHA256(p)
	return p
}

func TestUpdatePlanClosedWireAndLiteralSeal(t *testing.T) {
	p := planFixture(t)
	const want = "sha256:f247f2b78a4d30493aa80dd1fb6f546a7fb4766dbb95f59b5096e343614b1d5e"
	if p.PlanSHA256 != want {
		t.Fatalf("plan digest=%s", p.PlanSHA256)
	}
	raw := mustJSON(t, p)
	if _, err := DecodeUpdatePlan(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string]string{
		"unknown":   strings.Replace(string(raw), "}", ",\"extra\":1}", 1),
		"missing":   strings.Replace(string(raw), "\"kind\":\"UpdatePlan\",", "", 1),
		"null":      strings.Replace(string(raw), "\"source\":{", "\"source\":null,\"unused\":{", 1),
		"duplicate": strings.Replace(string(raw), "{\"apiVersion\":", "{\"apiVersion\":\"x\",\"apiVersion\":", 1),
	} {
		if _, err := DecodeUpdatePlan([]byte(mutated)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestUpdatePlanSealExcludesOnlyTopLevelCreatedAt(t *testing.T) {
	p := planFixture(t)
	base, _ := ComputeUpdatePlanSHA256(p)
	p.CreatedAt = "2026-06-02T00:00:00Z"
	if got, _ := ComputeUpdatePlanSHA256(p); got != base {
		t.Fatal("createdAt changed seal")
	}
	p.Actions[0].Action.Argv[1] = "--changed"
	if got, _ := ComputeUpdatePlanSHA256(p); got == base {
		t.Fatal("nested action change excluded from seal")
	}
}

func TestUpdatePlanRejectsDevelopmentAndForgedRequestInput(t *testing.T) {
	p := planFixture(t)
	p.TrustProfile.ID, p.TrustProfile.Assurance = bootstrap.ProfileDevelopment, bootstrap.DevelopmentUnverified
	p.PlanSHA256, _ = ComputeUpdatePlanSHA256(p)
	if p.Validate() == nil {
		t.Fatal("development stable plan accepted")
	}
	if _, err := BuildStableUpdatePlan(StablePlanInput{}); err == nil {
		t.Fatal("zero stable input accepted")
	}
	if _, ok := any(&DevelopmentUpdatePlan{}).(*UpdatePlan); ok {
		t.Fatal("development output converted to stable plan")
	}
	inputType := reflect.TypeOf(StablePlanInput{})
	for i := 0; i < inputType.NumField(); i++ {
		if inputType.Field(i).Type == reflect.TypeOf(PlanRequest{}) {
			t.Fatal("stable input accepts caller request triple")
		}
	}
}

func TestUpdatePlanSchemaOracle(t *testing.T) {
	raw, err := os.ReadFile("../../schema/update-plan.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	if err = c.AddResource("https://schemas.invalid/update-plan.v2.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("https://schemas.invalid/update-plan.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	value := func(p UpdatePlan) any {
		b := mustJSON(t, p)
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	p := planFixture(t)
	if err = s.Validate(value(p)); err != nil {
		t.Fatal(err)
	}
	cloneValue := func() map[string]any {
		b := mustJSON(t, p)
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown top-level": func(v map[string]any) { v["unknown"] = true },
		"missing top-level": func(v map[string]any) { delete(v, "kind") },
		"null top-level":    func(v map[string]any) { v["source"] = nil },
		"request digest": func(v map[string]any) {
			v["requests"].([]any)[0].(map[string]any)["grantSHA256"] = "sha256:UPPER"
		},
		"timeout bound": func(v map[string]any) {
			v["actions"].([]any)[0].(map[string]any)["timeoutMillis"] = float64(3600001)
		},
		"output path": func(v map[string]any) {
			v["outputs"].([]any)[0].(map[string]any)["path"] = "../escape"
		},
		"output control path": func(v map[string]any) {
			v["outputs"].([]any)[0].(map[string]any)["path"] = "generated\x00escape"
		},
		"output digest": func(v map[string]any) {
			v["outputs"].([]any)[0].(map[string]any)["contentSHA256"] = "bad"
		},
		"calendar invalid timestamp": func(v map[string]any) {
			v["createdAt"] = "2026-02-30T00:00:00Z"
		},
		"non-leap timestamp": func(v map[string]any) {
			v["createdAt"] = "2026-02-29T00:00:00Z"
		},
	} {
		bad := cloneValue()
		mutate(bad)
		if s.Validate(bad) == nil {
			t.Fatalf("schema accepted %s", name)
		}
	}
	bad := value(p).(map[string]any)
	bad["trustProfile"].(map[string]any)["id"] = "development"
	if s.Validate(bad) == nil {
		t.Fatal("development profile accepted by stable schema")
	}
	bad = value(p).(map[string]any)
	bad["actions"].([]any)[0].(map[string]any)["provider"].(map[string]any)["templatePath"] = "x/../y"
	if s.Validate(bad) == nil {
		t.Fatal("traversal accepted by schema")
	}
	// Linkage is deliberately a Go invariant above the JSON grammar. Re-seal
	// each altered DTO so this proves the rejection is not merely seal drift.
	linked := p
	linked.Actions = clonePlanActions(p.Actions)
	linked.Actions[0].RequestSHA256 = d('d')
	linked.PlanSHA256, err = ComputeUpdatePlanSHA256(linked)
	if err != nil {
		t.Fatal(err)
	}
	if linked.Validate() == nil {
		t.Fatal("Go validation accepted action/request mismatch")
	}
	linked = p
	linked.Actions = clonePlanActions(p.Actions)
	linked.Actions[0].OperationInputsSHA256 = d('d')
	linked.PlanSHA256, err = ComputeUpdatePlanSHA256(linked)
	if err != nil {
		t.Fatal(err)
	}
	if linked.Validate() == nil {
		t.Fatal("Go validation accepted action/operation mismatch")
	}
	for name, mutate := range map[string]func(*UpdatePlan){
		"output control path": func(v *UpdatePlan) { v.Outputs[0].Path = "generated\x00escape" },
		"calendar invalid":    func(v *UpdatePlan) { v.CreatedAt = "2026-02-30T00:00:00Z" },
		"non-leap date":       func(v *UpdatePlan) { v.CreatedAt = "2026-02-29T00:00:00Z" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			bad.Outputs = append([]PlanOutput(nil), p.Outputs...)
			mutate(&bad)
			bad.PlanSHA256, err = ComputeUpdatePlanSHA256(bad)
			if err != nil {
				t.Fatal(err)
			}
			if bad.Validate() == nil {
				t.Fatal("Go plan validation accepted invalid schema facet")
			}
			if _, err := DecodeUpdatePlan(mustJSON(t, bad)); err == nil {
				t.Fatal("Go stable plan decoder accepted invalid schema facet")
			}
		})
	}
	// A Draft 2020 schema validates parsed JSON values; standard JSON Schema
	// cannot distinguish lexical 100 from 100.0 or 1 from 1.0. Strict Go
	// decoding remains the required raw-wire facet, just as it does for
	// duplicate member detection.
	for name, raw := range map[string]string{
		"timeout 100.0": strings.Replace(string(mustJSON(t, p)), `"timeoutMillis":100`, `"timeoutMillis":100.0`, 1),
		"profile 1.0":   strings.Replace(string(mustJSON(t, p)), `"definitionVersion":1`, `"definitionVersion":1.0`, 1),
	} {
		var parsed any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatal(err)
		}
		if !schemaAccepts(s, parsed) {
			t.Fatalf("schema unexpectedly rejected parsed %s", name)
		}
		if _, err := DecodeUpdatePlan([]byte(raw)); err == nil {
			t.Fatalf("strict Go decoder accepted lexical %s", name)
		}
	}
}

func TestStablePlanFixtureUsesPublicRuntimeAndResolution(t *testing.T) {
	runtime, resolution, _ := planRuntime(t)
	if runtime == nil || resolution == nil || !resolution.ValidFor(runtime, runtime.Binding()) {
		t.Fatal("public stable runtime fixture did not produce a bound resolution")
	}
}

type stablePlanAuthorizationFixture struct {
	runtime    *trustverify.Runtime
	resolution *trustverify.VerifiedResolution
	fixture    *readerFixture
	permit     *trustverify.ExecutionPermit
	input      StablePlanInput
}

func TestBuildStableUpdatePlanUsesAuthorizedOpaquePermit(t *testing.T) {
	f := newStablePlanAuthorizationFixture(t)
	plan, err := BuildStableUpdatePlan(f.input)
	if err != nil {
		t.Fatalf("BuildStableUpdatePlan() error = %v", err)
	}
	ref, err := f.runtime.PersistentApprovalReference(f.permit)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Requests, []PlanRequest{{RequestSHA256: ref.RequestSHA256, GrantSHA256: ref.GrantSHA256, ApprovalCAS: ref.ApprovalCAS}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plan request evidence = %#v, want %#v", got, want)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("authorized plan Validate() = %v", err)
	}
	if _, err := DecodeUpdatePlan(mustJSON(t, plan)); err != nil {
		t.Fatalf("authorized plan DecodeUpdatePlan() = %v", err)
	}
	if got, err := BuildStableUpdatePlan(f.input); err != nil || got.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("repeat BuildStableUpdatePlan() = (%v, %v), want deterministic seal", got, err)
	}
	inputType := reflect.TypeOf(StablePlanInput{})
	for i := 0; i < inputType.NumField(); i++ {
		if inputType.Field(i).Type == reflect.TypeOf(PlanRequest{}) || inputType.Field(i).Type == reflect.TypeOf(trustverify.PersistentApprovalReference{}) {
			t.Fatalf("stable builder accepts caller-created approval evidence through %s", inputType.Field(i).Name)
		}
	}
	// A byte-identical public triple is evidence only. There is deliberately no
	// StablePlanInput field through which it could replace the opaque permit.
	_ = PlanRequest{RequestSHA256: ref.RequestSHA256, GrantSHA256: ref.GrantSHA256, ApprovalCAS: ref.ApprovalCAS}
}

func TestBuildStableUpdatePlanRejectsHostilePermitAndSealedEvidence(t *testing.T) {
	t.Run("nil and zero permits", func(t *testing.T) {
		f := newStablePlanAuthorizationFixture(t)
		for name, permit := range map[string]*trustverify.ExecutionPermit{"nil": nil, "zero": {}} {
			t.Run(name, func(t *testing.T) {
				in := f.input
				in.Permits = []*trustverify.ExecutionPermit{permit}
				if _, err := BuildStableUpdatePlan(in); err == nil {
					t.Fatal("invalid permit accepted")
				}
			})
		}
	})
	t.Run("foreign runtime permit", func(t *testing.T) {
		local, foreign := newStablePlanAuthorizationFixture(t), newStablePlanAuthorizationFixture(t)
		in := local.input
		in.Permits = []*trustverify.ExecutionPermit{foreign.permit}
		if _, err := BuildStableUpdatePlan(in); err == nil {
			t.Fatal("foreign-runtime permit accepted")
		}
	})
	t.Run("expired permit", func(t *testing.T) {
		f := newStablePlanAuthorizationFixture(t)
		f.fixture.now = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := BuildStableUpdatePlan(f.input); err == nil {
			t.Fatal("expired permit accepted")
		}
	})
	t.Run("human permit", func(t *testing.T) {
		f := newHumanPlanPermitFixture(t)
		if _, err := BuildStableUpdatePlan(f.input); err == nil {
			t.Fatal("human permit accepted for persistent stable plan")
		}
	})
	t.Run("changed action operation digest", func(t *testing.T) {
		f := newStablePlanAuthorizationFixture(t)
		in := f.input
		in.OperationInputsSHA256 = d('f')
		if _, err := BuildStableUpdatePlan(in); err == nil {
			t.Fatal("changed operation digest accepted")
		}
	})
	t.Run("resolution-backed lock mismatches", func(t *testing.T) {
		f := newStablePlanAuthorizationFixture(t)
		for name, mutate := range map[string]func(*StablePlanInput){
			"root subject": func(in *StablePlanInput) {
				in.Source.Root.Root.TemplatePath = "other"
				in.Source.Root.RootLockSHA256, _ = ComputeRootLockSHA256(in.Source.Root)
				in.Source.Dependencies.RootLockSHA256 = in.Source.Root.RootLockSHA256
				in.Source.Dependencies.LockSHA256, _ = ComputeTemplateLockSHA256(in.Source.Dependencies)
			},
			"source profile": func(in *StablePlanInput) {
				in.Source.Root.TrustProfile.ConfigSHA256 = d('f')
				in.Source.Root.RootLockSHA256, _ = ComputeRootLockSHA256(in.Source.Root)
				in.Source.Dependencies.TrustProfile = in.Source.Root.TrustProfile
				in.Source.Dependencies.RootLockSHA256 = in.Source.Root.RootLockSHA256
				in.Source.Dependencies.LockSHA256, _ = ComputeTemplateLockSHA256(in.Source.Dependencies)
			},
			"target profile": func(in *StablePlanInput) {
				in.Target.Root.TrustProfile.AuthoritySHA256 = d('f')
				in.Target.Root.RootLockSHA256, _ = ComputeRootLockSHA256(in.Target.Root)
				in.Target.Dependencies.TrustProfile = in.Target.Root.TrustProfile
				in.Target.Dependencies.RootLockSHA256 = in.Target.Root.RootLockSHA256
				in.Target.Dependencies.LockSHA256, _ = ComputeTemplateLockSHA256(in.Target.Dependencies)
			},
		} {
			t.Run(name, func(t *testing.T) {
				in := cloneStablePlanInput(f.input)
				mutate(&in)
				if _, err := BuildStableUpdatePlan(in); err == nil {
					t.Fatal("mismatched lock accepted")
				}
			})
		}
	})
	t.Run("sealed evidence substitutions", func(t *testing.T) {
		f := newStablePlanAuthorizationFixture(t)
		plan, err := BuildStableUpdatePlan(f.input)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*UpdatePlan){
			"request":  func(p *UpdatePlan) { p.Requests[0].RequestSHA256 = d('d') },
			"grant":    func(p *UpdatePlan) { p.Requests[0].GrantSHA256 = d('e') },
			"approval": func(p *UpdatePlan) { p.Requests[0].ApprovalCAS = d('f') },
		} {
			t.Run(name, func(t *testing.T) {
				bad := *plan
				bad.Requests = append([]PlanRequest(nil), plan.Requests...)
				mutate(&bad)
				if err := bad.Validate(); err == nil {
					t.Fatal("substituted sealed evidence accepted")
				}
			})
		}
	})
}

type acceptingPlanReviewer struct{}

func (acceptingPlanReviewer) Review(context.Context, trustverify.HumanReview) (bool, error) {
	return true, nil
}

func newStablePlanAuthorizationFixture(t *testing.T) stablePlanAuthorizationFixture {
	t.Helper()
	f := newReaderFixture(t)
	key := readerKey("plan-approver")
	policy := configurePlanApprover(t, f, key, false)
	runtime, resolution := newPlanRuntime(t, f, trustverify.StableOptions{Profile: bootstrap.ProfileOSS, Project: &readerProject{f: f}, Policy: &readerPolicy{f: f}, External: &readerExternal{f: f}, Bundle: &readerBundle{f: f}, Evidence: readerStore(f.store), Objects: f.objects, Clock: readerClock{f: f}})
	op, request := planOperationAndRequest(t, runtime.Binding(), resolution.Subject(), f.project.ProjectID)
	permit, refs := planPersistentPermit(t, f, runtime, resolution, policy, key, op, request)
	return stablePlanAuthorizationFixture{runtime: runtime, resolution: resolution, fixture: f, permit: permit, input: stablePlanInput(t, runtime, resolution, op, request, permit, refs)}
}

func newHumanPlanPermitFixture(t *testing.T) stablePlanAuthorizationFixture {
	t.Helper()
	f := newReaderFixture(t)
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	policy.AllowInvocationHuman = true
	var err error
	policy.PolicySHA256, err = policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy.PolicyJSON, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.ExpectedPolicySHA256 = policy.PolicySHA256
	runtime, resolution := newPlanRuntime(t, f, trustverify.StableOptions{Profile: bootstrap.ProfileOSS, Project: &readerProject{f: f}, Policy: &readerPolicy{f: f}, External: &readerExternal{f: f}, Bundle: &readerBundle{f: f}, Evidence: readerStore(f.store), Objects: f.objects, Clock: readerClock{f: f}, Transport: "direct-interactive-cli", Human: acceptingPlanReviewer{}})
	op, request := planOperationAndRequest(t, runtime.Binding(), resolution.Subject(), f.project.ProjectID)
	human, err := runtime.ReviewHuman(context.Background(), resolution, op, request)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := runtime.AuthorizeHuman(context.Background(), resolution, op, request, human)
	if err != nil {
		t.Fatal(err)
	}
	return stablePlanAuthorizationFixture{runtime: runtime, resolution: resolution, fixture: f, permit: permit, input: stablePlanInput(t, runtime, resolution, op, request, permit, trustverify.ApprovalRefs{})}
}

func configurePlanApprover(t *testing.T, f *readerFixture, key ed25519.PrivateKey, human bool) trustverify.ExecutionPolicy {
	t.Helper()
	var policy trustverify.ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	policy.Principals = append(policy.Principals, trustverify.Principal{ID: "principal:zz-plan-approver"})
	policy.Approvers = []trustverify.Approver{{ID: "plan-approver", PrincipalID: "principal:zz-plan-approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(public), PublicKeyBase64: base64.StdEncoding.EncodeToString(public), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: f.project.ProjectID, OperationScope: "update", ActionKind: "command", Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath}}}}
	policy.AllowInvocationHuman = human
	var err error
	policy.PolicySHA256, err = policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy.PolicyJSON, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.ExpectedPolicySHA256 = policy.PolicySHA256
	return policy
}

func newPlanRuntime(t *testing.T, f *readerFixture, options trustverify.StableOptions) (*trustverify.Runtime, *trustverify.VerifiedResolution) {
	t.Helper()
	runtime, err := trustverify.NewRuntime(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := runtime.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, resolution
}

func planOperationAndRequest(t *testing.T, binding bootstrap.ProfileBinding, subject trustverify.Subject, projectID string) (trustverify.OperationInputs, trustverify.ExecutionRequest) {
	t.Helper()
	bindingDigest, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, binding)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("plan frozen content")
	toolBytes := []byte("plan frozen tool")
	closure, err := trustverify.ComputeContentClosureSHA256([]trustverify.ContentEntry{{Root: "provider", Path: "run.sh", Mode: "100755", ContentSHA256: evidencecas.Digest(content)}})
	if err != nil {
		t.Fatal(err)
	}
	options, err := trustverify.ComputeToolOptionsSHA256([]string{"--exact"})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := trustverify.ComputeEnvironmentPolicySHA256(trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}})
	if err != nil {
		t.Fatal(err)
	}
	provider := trustverify.Provider{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}
	action := trustverify.Action{ID: "plan.action", Kind: "command", Phase: "standalone", Argv: []string{"plan.tool", "--exact"}, ContentClosureSHA256: closure}
	tool := trustverify.Tool{ID: "plan.tool", Version: "v1", BinarySHA256: evidencecas.Digest(toolBytes), OptionsSHA256: options}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bindingDigest, ProjectID: projectID, Scope: "update", PreimageSHA256: evidencecas.Digest([]byte("plan preimage")), AnswersSHA256: evidencecas.Digest([]byte("plan answers")), Subjects: []trustverify.Provider{provider}, Actions: []trustverify.ActionMaterial{{Provider: provider, Action: action, Tool: tool, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: environment, TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}}}
	opDigest, err := trustverify.ComputeOperationInputsSHA256(op)
	if err != nil {
		t.Fatal(err)
	}
	request := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bindingDigest, OperationInputsSHA256: opDigest, ProjectID: projectID, Scope: "update", Provider: provider, Action: action, Tool: tool, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: environment, TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}
	request.RequestSHA256, err = request.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return op, request
}

func planPersistentPermit(t *testing.T, f *readerFixture, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, policy trustverify.ExecutionPolicy, key ed25519.PrivateKey, operation trustverify.OperationInputs, request trustverify.ExecutionRequest) (*trustverify.ExecutionPermit, trustverify.ApprovalRefs) {
	t.Helper()
	approval := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: request.RequestSHA256, ProfileBindingSHA256: request.ProfileBindingSHA256, OperationInputsSHA256: request.OperationInputsSHA256, ProjectID: request.ProjectID, Scope: request.Scope, ApproverID: policy.Approvers[0].ID, IdentityClass: policy.Approvers[0].IdentityClass, ExecutionPolicySHA256: policy.PolicySHA256, Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, KeyFingerprint: policy.Approvers[0].KeyFingerprint}
	var err error
	approval.GrantSHA256, err = approval.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(bootstrap.EncodeSignature(ed25519.Sign(key, readerRawDigest(t, approval.GrantSHA256))))
	approval.SignatureCAS = readerPut(f.store, signature)
	raw, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	refs := trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: readerPut(f.store, raw)}
	permit, err := runtime.Authorize(context.Background(), resolution, operation, request, refs)
	if err != nil {
		t.Fatal(err)
	}
	return permit, refs
}

func stablePlanInput(t *testing.T, runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, operation trustverify.OperationInputs, request trustverify.ExecutionRequest, permit *trustverify.ExecutionPermit, _ trustverify.ApprovalRefs) StablePlanInput {
	t.Helper()
	root := RootTemplateLock{APIVersion: RootTemplateLockAPIVersion, Kind: RootTemplateLockKind, TrustProfile: runtime.Binding(), Policy: PolicyBinding{PolicySHA256: runtime.Binding().PolicySHA256}, Root: RootSubjectFromTrust(resolution.Subject(), bootstrap.PublisherEvidence{StatementCAS: resolution.Evidence().StatementCAS, SignatureCAS: resolution.Evidence().SignatureCAS, KeyFingerprint: resolution.Evidence().KeyFingerprint}, resolution.Evidence().CheckpointCAS, resolution.Evidence().InclusionProofCAS), Renderer: RendererIdentity{Name: "go-text-template", Version: "v2"}}
	var err error
	root.RootLockSHA256, err = ComputeRootLockSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := TemplateLock{APIVersion: TemplateLockAPIVersion, Kind: DependencyExportLockKind, TrustProfile: runtime.Binding(), RootLockSHA256: root.RootLockSHA256, Dependencies: []DependencySubject{}}
	dependencies.LockSHA256, err = ComputeTemplateLockSHA256(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	planAction := PlanAction{RequestSHA256: request.RequestSHA256, OperationInputsSHA256: request.OperationInputsSHA256, Provider: PlanProvider(request.Provider), Action: PlanActionDefinition(request.Action), Tool: PlanTool(request.Tool), WorkingDirectoryScope: PlanWorkingDirectory(request.WorkingDirectoryScope), EnvironmentPolicySHA256: request.EnvironmentPolicySHA256, TimeoutMillis: request.TimeoutMillis, Migration: PlanMigration(request.Migration)}
	return StablePlanInput{Runtime: runtime, Source: StablePlanLockInput{Resolution: resolution, Root: root, Dependencies: dependencies}, Target: StablePlanLockInput{Resolution: resolution, Root: root, Dependencies: dependencies}, OperationInputsSHA256: request.OperationInputsSHA256, Permits: []*trustverify.ExecutionPermit{permit}, PreimageSHA256: operation.PreimageSHA256, Actions: []PlanAction{planAction}, Outputs: []PlanOutput{{Path: "generated.txt", ContentSHA256: evidencecas.Digest([]byte("generated"))}}, CreatedAt: "2026-06-01T00:00:00Z"}
}

func cloneStablePlanInput(in StablePlanInput) StablePlanInput {
	in.Actions = clonePlanActions(in.Actions)
	in.Outputs = append([]PlanOutput(nil), in.Outputs...)
	in.Permits = append([]*trustverify.ExecutionPermit(nil), in.Permits...)
	return in
}

type readerFixture struct {
	store   map[string][]byte
	ext     bootstrap.ProvisionedSnapshot
	bundle  bootstrap.Bundle
	policy  trustverify.ExecutionPolicySnapshot
	project trustverify.ProjectContext
	objects trustverify.GitObjectReader
	subject trustverify.Subject
	refs    trustverify.EvidenceRefs
	now     time.Time
}
type readerStore map[string][]byte

func (s readerStore) Read(_ context.Context, d string) ([]byte, error) {
	b, ok := s[d]
	if !ok {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), b...), nil
}

type readerExternal struct {
	f     *readerFixture
	calls int
}

func (r *readerExternal) Load(context.Context) (bootstrap.ProvisionedSnapshot, error) {
	r.calls++
	return r.f.ext, nil
}

type readerBundle struct {
	f     *readerFixture
	calls int
}

func (r *readerBundle) Load(context.Context) (bootstrap.Bundle, error) {
	r.calls++
	return r.f.bundle, nil
}

type readerPolicy struct {
	f     *readerFixture
	calls int
}

func (r *readerPolicy) Load(context.Context) (trustverify.ExecutionPolicySnapshot, error) {
	r.calls++
	return r.f.policy, nil
}

type readerProject struct {
	f     *readerFixture
	calls int
}

func (r *readerProject) Load(context.Context) (trustverify.ProjectContext, error) {
	r.calls++
	return r.f.project, nil
}

type readerClock struct{ f *readerFixture }

func (r readerClock) Now() time.Time { return r.f.now }

type readerObjectStore struct {
	objects map[string]trustverify.GitObject
}

func (s *readerObjectStore) ReadObject(_ context.Context, _ trustverify.SourceOrigin, id trustverify.ObjectID) (trustverify.GitObject, error) {
	o, ok := s.objects[string(id)]
	if !ok {
		return trustverify.GitObject{}, errors.New("object missing")
	}
	return trustverify.GitObject{Kind: o.Kind, Data: append([]byte(nil), o.Data...)}, nil
}

func readerDigest(b []byte) string { return evidencecas.Digest(b) }
func readerPut(s map[string][]byte, b []byte) string {
	d := readerDigest(b)
	s[d] = append([]byte(nil), b...)
	return d
}
func readerKey(label string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(h[:])
}
func readerRawDigest(t *testing.T, d string) []byte {
	t.Helper()
	b, err := hex.DecodeString(d[len("sha256:"):])
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func readerHash(h bootstrap.MerkleHash) string { return "sha256:" + hex.EncodeToString(h[:]) }

func readerOID(kind string, data []byte) string {
	p := []byte(kind + " " + readerItoa(len(data)) + "\x00")
	p = append(p, data...)
	h := sha1.Sum(p)
	return hex.EncodeToString(h[:])
}
func readerItoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := make([]byte, 0, 10)
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}
func readerHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func readerSourceFixture() (trustverify.GitObjectReader, trustverify.Subject) {
	objects := &readerObjectStore{objects: map[string]trustverify.GitObject{}}
	add := func(kind string, data []byte) string {
		id := readerOID(kind, data)
		objects.objects[id] = trustverify.GitObject{Kind: kind, Data: data}
		return id
	}
	empty := add("tree", nil)
	script := []byte("#!/bin/sh\necho ok\n")
	contract := []byte("{\"apiVersion\":\"fixture\"}\n")
	scriptID, contractID := add("blob", script), add("blob", contract)
	tree := append([]byte("40000 empty\x00"), readerHex(empty)...)
	tree = append(tree, []byte("100755 run.sh\x00")...)
	tree = append(tree, readerHex(scriptID)...)
	tree = append(tree, []byte("100644 template.contract.json\x00")...)
	tree = append(tree, readerHex(contractID)...)
	root := add("tree", tree)
	commit := add("commit", []byte("tree "+root+"\n\nauthor fixture <fixture@example.test> 0 +0000\n"))
	entries := []trustverify.SourceEntry{{Path: "empty", Kind: "directory", Mode: "40000"}, {Path: "run.sh", Kind: "file", Mode: "100755", ContentSHA256: readerDigest(script)}, {Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: readerDigest(contract)}}
	treeDigest, _ := readerFramed("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	contractDigest, _ := readerFramed("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", readerDigest(contract)})
	return objects, trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: commit, Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}
func readerFramed(domain string, v any) (string, error) {
	b, err := canonicaljson.Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func newReaderFixture(t *testing.T) *readerFixture {
	t.Helper()
	objects, subject := readerSourceFixture()
	store := map[string][]byte{}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	anchor, publisher := readerKey("reader-anchor"), readerKey("reader-publisher")
	anchorPub, publisherPub := anchor.Public().(ed25519.PublicKey), publisher.Public().(ed25519.PublicKey)
	publisherRef := readerPut(store, []byte(bootstrap.EncodePublicKey(publisherPub)))
	envelope := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "reader-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: publisherRef, Issuer: "publisher", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	var err error
	envelope.PayloadSHA256, err = envelope.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	anchorSig := readerPut(store, []byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, readerRawDigest(t, envelope.PayloadSHA256)))))
	envelope.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: anchorSig}}
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: "publisher", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
	statementRaw, _ := json.Marshal(statement)
	statementCAS := readerPut(store, statementRaw)
	statementDigest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	signatureCAS := readerPut(store, []byte(bootstrap.EncodeSignature(ed25519.Sign(publisher, readerRawDigest(t, statementDigest)))))
	envelopeLeaf, statementLeaf := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256)), bootstrap.HashLeaf([]byte(statementCAS))
	checkpointRaw, _ := json.Marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: envelope.AuthorityID, TreeSize: 2, RootHash: readerHash(bootstrap.HashChildren(envelopeLeaf, statementLeaf))})
	checkpointCAS := readerPut(store, checkpointRaw)
	envelopeProofRaw, _ := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 2, Hashes: []string{readerHash(statementLeaf)}})
	envelopeProofCAS := readerPut(store, envelopeProofRaw)
	statementProofRaw, _ := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 2, Hashes: []string{readerHash(envelopeLeaf)}})
	statementProofCAS := readerPut(store, statementProofRaw)
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: envelope.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: 0, TreeSize: 2, CheckpointDigest: checkpointCAS}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	rawEnvelope, _ := json.Marshal(envelope)
	rawReceipt, _ := json.Marshal(receipt)
	descriptor := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: envelope.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: statement.PolicyOrigin, Issuer: statement.Issuer, SourceOrigin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, Predicate: statement.Predicate, Usage: statement.Usage}}}
	descriptor.DescriptorSHA256 = descriptor.ComputedSHA256()
	descriptorRaw, _ := json.Marshal(descriptor)
	provisioning := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256, AuthenticationEvidenceSHA256: readerDigest([]byte("fixture-auth")), EvidenceClass: bootstrap.EvidenceProduction}
	provisioning.ProvisioningSHA256 = provisioning.ComputedSHA256()
	provisioningRaw, _ := json.Marshal(provisioning)
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: descriptor.DescriptorSHA256, ProvisioningSHA256: provisioning.ProvisioningSHA256, AuthorityID: envelope.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 2, CheckpointDigest: checkpointCAS}
	state.StateSHA256 = state.ComputedSHA256()
	stateRaw, _ := json.Marshal(state)
	policy := trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "reader-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: statement.PolicyOrigin, Issuer: statement.Issuer, Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, Predicate: statement.Predicate, Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{}, AllowInvocationHuman: false, MaxTimeoutMillis: 1000}
	policy.PolicySHA256, err = policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, _ := json.Marshal(policy)
	return &readerFixture{store: store, ext: bootstrap.ProvisionedSnapshot{DescriptorJSON: descriptorRaw, ProvisioningJSON: provisioningRaw, ExpectedDescriptorSHA256: descriptor.DescriptorSHA256, ExpectedProvisioningSHA256: provisioning.ProvisioningSHA256, OSSStateJSON: stateRaw, ExpectedOSSStateSHA256: state.StateSHA256, InitialOSSStateSHA256: state.StateSHA256}, bundle: bootstrap.Bundle{Envelope: rawEnvelope, Receipt: rawReceipt, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: checkpointCAS, InclusionProofCAS: envelopeProofCAS}}, policy: trustverify.ExecutionPolicySnapshot{PolicyJSON: policyRaw, ExpectedPolicySHA256: policy.PolicySHA256}, project: trustverify.ProjectContext{ProjectID: "reader-project", SubmitterPrincipalID: "principal:submitter", MinimumProfile: "oss"}, objects: objects, subject: subject, refs: trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signatureCAS, KeyFingerprint: bootstrap.Fingerprint(publisherPub), CheckpointCAS: checkpointCAS, InclusionProofCAS: statementProofCAS}, now: now}
}

func planRuntime(t *testing.T) (*trustverify.Runtime, *trustverify.VerifiedResolution, *readerFixture) {
	t.Helper()
	f := newReaderFixture(t)
	ext, pol, bundle, project := &readerExternal{f: f}, &readerPolicy{f: f}, &readerBundle{f: f}, &readerProject{f: f}
	r, err := trustverify.NewRuntime(context.Background(), trustverify.StableOptions{Profile: bootstrap.ProfileOSS, Project: project, Policy: pol, External: ext, Bundle: bundle, Evidence: readerStore(f.store), Objects: f.objects, Clock: readerClock{f: f}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	return r, res, f
}
