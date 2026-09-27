package trustverify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	js "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

type approvalMemoryCAS map[string][]byte

func (m approvalMemoryCAS) Read(ctx context.Context, d string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, ok := m[d]
	if !ok {
		return nil, errMissing{}
	}
	return append([]byte(nil), b...), nil
}

func approvalFixture(t *testing.T) (*ExecutionPolicy, *ExecutionRequest, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	pub := priv.Public().(ed25519.PublicKey)
	p := &ExecutionPolicy{APIVersion: ExecutionPolicyAPIVersion, PolicyID: "policy.test", Profile: "oss", MinimumProfile: "oss", Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, Principals: []Principal{{"principal:approver"}, {"principal:publisher"}}, IssuerPrincipals: []IssuerPrincipal{{"issuer.test", "principal:publisher"}}, SourceRules: []SourceRule{{"policy.test", "issuer.test", "origin.test", ".", "predicate.test", "tplaiter-publisher-statement-v1"}}, Approvers: []Approver{{ID: "approver.test", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(pub), PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, Scopes: []ApprovalScope{{"project.test", "run", "command", "origin.test", "."}}}}, MaxTimeoutMillis: 1000}
	d, e := p.ComputePolicySHA256()
	if e != nil {
		t.Fatal(e)
	}
	p.PolicySHA256 = d
	digest := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	r := &ExecutionRequest{APIVersion: ExecutionRequestAPIVersion, ProfileBindingSHA256: digest('1'), OperationInputsSHA256: digest('2'), ProjectID: "project.test", Scope: "run", Provider: Provider{"origin.test", ".", strings.Repeat("a", 40), digest('3'), digest('4')}, Action: Action{"action.test", "command", "standalone", false, []string{"tool.test", "--exact"}, digest('5')}, Tool: Tool{"tool.test", "1", digest('6'), digest('7')}, WorkingDirectoryScope: WorkingDirectoryScope{"project", "."}, EnvironmentPolicySHA256: digest('8'), TimeoutMillis: 100, Migration: Migration{Kind: "none"}}
	d, e = r.ComputeRequestSHA256()
	if e != nil {
		t.Fatal(e)
	}
	r.RequestSHA256 = d
	return p, r, priv
}

func TestExecutionPolicyAndRequestPositiveStrictWire(t *testing.T) {
	p, r, _ := approvalFixture(t)
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeExecutionPolicy(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got.PolicySHA256 != p.PolicySHA256 {
		t.Fatal("policy changed")
	}
	raw, e = json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	gotR, e := DecodeExecutionRequest(raw)
	if e != nil {
		t.Fatal(e)
	}
	if gotR.RequestSHA256 != r.RequestSHA256 {
		t.Fatal("request changed")
	}
	if _, e := DecodeExecutionRequest(append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)); e == nil {
		t.Fatal("unknown request member accepted")
	}
	withoutShell := []byte(strings.Replace(string(raw), `"shell":false,`, "", 1))
	if _, e := DecodeExecutionRequest(withoutShell); e == nil {
		t.Fatal("missing nested shell accepted")
	}
}

func TestExecutionPolicyKeyCodecExactVectors(t *testing.T) {
	good := "//////////////////////////////////////////8="
	key, e := decodeExecutionPolicyPublicKey(good)
	if e != nil || bootstrap.Fingerprint(key) != "sha256:af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051" {
		t.Fatalf("key=%x err=%v", key, e)
	}
	for _, bad := range []string{"__________________________________________8", "__________________________________________8=", strings.TrimSuffix(good, "="), good + "=", " " + good, good + "\n", strings.TrimSuffix(good, "=") + "9=", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33))} {
		if _, e := decodeExecutionPolicyPublicKey(bad); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestPersistentApprovalVerifiesCASAndRawDigestSignature(t *testing.T) {
	p, r, priv := approvalFixture(t)
	a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, KeyFingerprint: p.Approvers[0].KeyFingerprint}
	d, e := a.ComputeGrantSHA256()
	if e != nil {
		t.Fatal(e)
	}
	a.GrantSHA256 = d
	msg, e := digestBytes(d)
	if e != nil {
		t.Fatal(e)
	}
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(priv, msg)))
	a.SignatureCAS = evidencecas.Digest(sig)
	raw, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	cas := approvalMemoryCAS{evidencecas.Digest(raw): raw, a.SignatureCAS: sig}
	if e := VerifyPersistentApproval(context.Background(), cas, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), evidencecas.Digest(raw)); e != nil {
		t.Fatal(e)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	cas[a.SignatureCAS] = bad
	if e := VerifyPersistentApproval(context.Background(), cas, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), evidencecas.Digest(raw)); e == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestExecutionWireDigestExclusions(t *testing.T) {
	p, r, _ := approvalFixture(t)
	original := p.PolicySHA256
	p.AllowInvocationHuman = true
	d, e := p.ComputePolicySHA256()
	if e != nil || d == original {
		t.Fatal("policy semantic field excluded")
	}
	before := r.RequestSHA256
	r.Action.Argv = []string{"tool.test", "changed"}
	d, e = r.ComputeRequestSHA256()
	if e != nil || d == before {
		t.Fatal("ordered argv excluded")
	}
}

func TestExecutionMaterialDomainVectors(t *testing.T) {
	d := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	content, e := ComputeContentClosureSHA256([]ContentEntry{{"project", "config.yml", "100644", d('a')}, {"provider", "run.sh", "100755", d('b')}})
	if e != nil {
		t.Fatal(e)
	}
	options, e := ComputeToolOptionsSHA256([]string{"--exact", ""})
	if e != nil {
		t.Fatal(e)
	}
	env, e := ComputeEnvironmentPolicySHA256(EnvironmentPolicy{"tplaiter.dev/execution-environment/v1", false, []EnvironmentVariable{{"LANG", "C"}}, []string{}})
	if e != nil {
		t.Fatal(e)
	}
	p, r, _ := approvalFixture(t)
	op, e := ComputeOperationInputsSHA256(OperationInputs{"tplaiter.dev/operation-inputs/v1", r.ProfileBindingSHA256, r.ProjectID, r.Scope, d('c'), d('d'), []Provider{r.Provider}, []ActionMaterial{{r.Provider, r.Action, r.Tool, r.WorkingDirectoryScope, env, r.TimeoutMillis, r.Migration}}})
	if e != nil {
		t.Fatal(e)
	}
	if content != "sha256:2da7cf6662b729d9f41dbd8e163faf98659ea86cabe11e445c740a622377034e" || options != "sha256:27aab956466c1911957890c461c0d21a4aa882a8c7cc1163a1e36243d9be3ef1" || env != "sha256:062449c8348ce0436f637c9ec64de0863348d8d2afef3b732eb2b302d0739c48" || op != "sha256:92f55978a2e8c98b6656b32118bf27eed94e511cdac48bd03c9c659afdf1a0cf" || p.PolicySHA256 == "" {
		t.Fatalf("unexpected material vectors %s %s %s %s", content, options, env, op)
	}
	if _, e := ComputeContentClosureSHA256([]ContentEntry{{"provider", "z", "100644", d('a')}, {"project", "a", "100644", d('b')}}); e == nil {
		t.Fatal("unsorted content accepted")
	}
}

func TestDirectDTOValidationAndExactMigrationWire(t *testing.T) {
	p, r, priv := approvalFixture(t)
	p.Principals[0].ID = "Principal:bad"
	if _, e := p.ComputePolicySHA256(); e == nil {
		t.Fatal("invalid direct policy hashed")
	}
	p, r, priv = approvalFixture(t)
	r.Action.Argv[0] = "other"
	if _, e := r.ComputeRequestSHA256(); e == nil {
		t.Fatal("invalid direct request hashed")
	}
	p, r, priv = approvalFixture(t)
	a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, KeyFingerprint: p.Approvers[0].KeyFingerprint}
	d, _ := a.ComputeGrantSHA256()
	a.GrantSHA256 = d
	msg, _ := digestBytes(d)
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(priv, msg)))
	a.SignatureCAS = evidencecas.Digest(sig)
	raw, _ := json.Marshal(a)
	cas := approvalMemoryCAS{evidencecas.Digest(raw): raw, a.SignatureCAS: sig}
	p.PolicySHA256 = "sha256:" + strings.Repeat("0", 64)
	if e := VerifyPersistentApproval(context.Background(), cas, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), evidencecas.Digest(raw)); e == nil {
		t.Fatal("mismatched direct policy accepted")
	}
	_, r, _ = approvalFixture(t)
	raw, _ = json.Marshal(r)
	bad := []byte(strings.Replace(string(raw), `"migration":{"kind":"none"}`, `"migration":{"kind":"none","from":"x"}`, 1))
	if _, e := DecodeExecutionRequest(bad); e == nil {
		t.Fatal("none migration extra field accepted")
	}
	bad = []byte(strings.Replace(string(raw), `"migration":{"kind":"none"}`, `"migration":{"kind":"version-transition"}`, 1))
	if _, e := DecodeExecutionRequest(bad); e == nil {
		t.Fatal("transition migration missing fields accepted")
	}
}

func TestExecutionSchemasCompileDraft2020(t *testing.T) {
	for _, name := range []string{"execution-request.v1.schema.json", "execution-approval.v1.schema.json", "execution-policy.v1.schema.json"} {
		raw, err := os.ReadFile("../../schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := js.NewCompiler()
		uri := "https://schemas.invalid/" + name
		if err := c.AddResource(uri, doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.Compile(uri); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func executionSchema(t *testing.T, name string) *js.Schema {
	t.Helper()
	raw, err := os.ReadFile("../../schema/" + name)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	c.AssertFormat()
	uri := "https://schemas.invalid/" + name
	if err = c.AddResource(uri, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(uri)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func schemaChecksJSON(t *testing.T, s *js.Schema, raw []byte) error {
	t.Helper()
	v, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(v)
}

func TestExecutionSchemasRuntimeParityFocused(t *testing.T) {
	p, r, _ := approvalFixture(t)
	policy, request := executionSchema(t, "execution-policy.v1.schema.json"), executionSchema(t, "execution-request.v1.schema.json")
	pb, _ := json.Marshal(p)
	rb, _ := json.Marshal(r)
	if err := schemaChecksJSON(t, policy, pb); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	if err := schemaChecksJSON(t, request, rb); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ExecutionPolicy)
	}{
		{"bad-principal", func(x *ExecutionPolicy) { x.Principals[0].ID = "Principal:bad" }},
		{"bad-policy-key", func(x *ExecutionPolicy) {
			x.Approvers[0].PublicKeyBase64 = "__________________________________________8="
		}},
		{"bad-scope", func(x *ExecutionPolicy) { x.Approvers[0].Scopes[0].TemplatePath = "../escape" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, _, _ := approvalFixture(t)
			tc.mutate(q)
			b, _ := json.Marshal(q)
			if err := schemaChecksJSON(t, policy, b); err == nil {
				t.Fatal("schema accepted invalid policy facet")
			}
			if _, err := q.ComputePolicySHA256(); err == nil {
				t.Fatal("runtime accepted invalid policy facet")
			}
		})
	}
	q, _, _ := approvalFixture(t)
	q.IssuerPrincipals[0].PrincipalID = "principal:unknown"
	if _, err := q.ComputePolicySHA256(); err == nil {
		t.Fatal("runtime accepted issuer mapping to unknown principal")
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(rb), `"migration":{"kind":"none"}`, `"migration":{"kind":"none","from":"x"}`, 1)),
		[]byte(strings.Replace(string(rb), `"migration":{"kind":"none"}`, `"migration":{"kind":"version-transition"}`, 1)),
		[]byte(strings.Replace(string(rb), `"commit":"`+strings.Repeat("a", 40)+`"`, `"commit":12`, 1)),
	} {
		if err := schemaChecksJSON(t, request, raw); err == nil {
			t.Fatal("schema accepted invalid request facet")
		}
		if _, err := DecodeExecutionRequest(raw); err == nil {
			t.Fatal("runtime accepted invalid request facet")
		}
	}
}

type approvalCASFunc func(context.Context, string) ([]byte, error)

func (f approvalCASFunc) Read(ctx context.Context, d string) ([]byte, error) { return f(ctx, d) }

func TestPersistentApprovalCASAndScopeBoundaries(t *testing.T) {
	p, r, priv := approvalFixture(t)
	a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, KeyFingerprint: p.Approvers[0].KeyFingerprint}
	a.GrantSHA256, _ = a.ComputeGrantSHA256()
	msg, _ := digestBytes(a.GrantSHA256)
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(priv, msg)))
	a.SignatureCAS = evidencecas.Digest(sig)
	raw, _ := json.Marshal(a)
	approvalDigest := evidencecas.Digest(raw)
	base := approvalMemoryCAS{approvalDigest: raw, a.SignatureCAS: sig}
	verify := func(store evidencecas.Reader) error {
		return VerifyPersistentApproval(context.Background(), store, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), approvalDigest)
	}
	if err := verify(base); err != nil {
		t.Fatal(err)
	}
	p.Approvers[0].Scopes[0].TemplatePath = "other"
	if err := verify(base); err == nil {
		t.Fatal("partial scope tuple accepted")
	}
	p.Approvers[0].Scopes[0].TemplatePath = "."
	if err := verify(approvalCASFunc(func(context.Context, string) ([]byte, error) { return []byte("altered"), nil })); err == nil {
		t.Fatal("CAS rehash mismatch accepted")
	}
	if err := verify(approvalCASFunc(func(context.Context, string) ([]byte, error) { return make([]byte, maxApprovalJSON+1), nil })); err == nil {
		t.Fatal("oversized approval accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyPersistentApproval(ctx, base, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), approvalDigest); err == nil {
		t.Fatal("canceled context accepted")
	}
	for _, after := range []string{approvalDigest, a.SignatureCAS} {
		t.Run("cancel-after-"+after[:14], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			store := approvalCASFunc(func(_ context.Context, d string) ([]byte, error) {
				b, err := base.Read(context.Background(), d)
				if d == after {
					cancel()
				}
				return b, err
			})
			err := VerifyPersistentApproval(ctx, store, p, r, r.OperationInputsSHA256, r.ProfileBindingSHA256, time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC), approvalDigest)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("post-read cancellation = %v", err)
			}
		})
	}
}

func TestExecutionPathAndValiditySchemaParity(t *testing.T) {
	p, r, _ := approvalFixture(t)
	request, policy, approval := executionSchema(t, "execution-request.v1.schema.json"), executionSchema(t, "execution-policy.v1.schema.json"), executionSchema(t, "execution-approval.v1.schema.json")
	for _, path := range []string{".", "тест/файл", ".hidden", "..."} {
		q := *r
		q.Provider.TemplatePath = path
		q.RequestSHA256 = ""
		d, err := q.ComputeRequestSHA256()
		if err != nil {
			t.Fatalf("runtime rejected valid path %q: %v", path, err)
		}
		q.RequestSHA256 = d
		b, _ := json.Marshal(q)
		if err := schemaChecksJSON(t, request, b); err != nil {
			t.Fatalf("schema rejected valid path %q: %v", path, err)
		}
	}
	for _, path := range []string{"", "../escape", "a/../b", "/a", "a/", `a\\b`, "a:b", "a\n", "a\x00b", strings.Repeat("т", 1025)} {
		q := *r
		q.Provider.TemplatePath = path
		q.RequestSHA256 = ""
		b, _ := json.Marshal(q)
		if _, err := q.ComputeRequestSHA256(); err == nil {
			t.Fatalf("runtime accepted invalid path %q", path)
		}
		if err := schemaChecksJSON(t, request, b); err == nil {
			t.Fatalf("schema accepted invalid path %q", path)
		}
	}
	for _, v := range []Validity{{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}} {
		q := *p
		q.Validity = v
		q.PolicySHA256 = ""
		d, err := q.ComputePolicySHA256()
		if err != nil {
			t.Fatal(err)
		}
		q.PolicySHA256 = d
		b, _ := json.Marshal(q)
		if err := schemaChecksJSON(t, policy, b); err != nil {
			t.Fatalf("policy schema rejected validity: %v", err)
		}
		a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: v, KeyFingerprint: p.Approvers[0].KeyFingerprint, GrantSHA256: "sha256:" + strings.Repeat("0", 64), SignatureCAS: "sha256:" + strings.Repeat("1", 64)}
		b, _ = json.Marshal(a)
		if err := schemaChecksJSON(t, approval, b); err != nil {
			t.Fatalf("approval schema rejected canonical validity: %v", err)
		}
	}
	for _, v := range []Validity{{"2030-01-01T00:00:00.1Z", "2031-01-01T00:00:00Z"}, {"2030-01-01T03:00:00+03:00", "2031-01-01T00:00:00Z"}, {"2030-99-01T00:00:00Z", "2031-01-01T00:00:00Z"}} {
		q := *p
		q.Validity = v
		q.PolicySHA256 = ""
		b, _ := json.Marshal(q)
		if _, err := q.ComputePolicySHA256(); err == nil {
			t.Fatalf("runtime accepted invalid validity %+v", v)
		}
		if err := schemaChecksJSON(t, policy, b); err == nil {
			t.Fatalf("policy schema accepted invalid validity %+v", v)
		}
		a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: v, KeyFingerprint: p.Approvers[0].KeyFingerprint, GrantSHA256: "sha256:" + strings.Repeat("0", 64), SignatureCAS: "sha256:" + strings.Repeat("1", 64)}
		b, _ = json.Marshal(a)
		if err := schemaChecksJSON(t, approval, b); err == nil {
			t.Fatalf("approval schema accepted invalid validity %+v", v)
		}
	}
}

func TestExecutionRequestGrantGoldenFraming(t *testing.T) {
	p, r, priv := approvalFixture(t)
	wantRequest := "sha256:6eb50f59924efd0747573bb4b9be075bd1f4b93fabd3878156f5ece3da62ccf9"
	r.RequestSHA256 = ""
	gotRequest, err := r.ComputeRequestSHA256()
	if err != nil || gotRequest != wantRequest {
		t.Fatalf("request golden got=%s want=%s err=%v", gotRequest, wantRequest, err)
	}
	r.RequestSHA256 = gotRequest
	a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: p.PolicySHA256, Validity: Validity{"2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"}, KeyFingerprint: p.Approvers[0].KeyFingerprint}
	a.GrantSHA256, err = a.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	// This literal is generated independently from the protocol preimage and
	// pins both the two excluded top-level fields and every signed member.
	wantGrant := "sha256:bdd7f495057f4cb32d07da9576d858b4b37e96a8904dadf7155866fd2493287a"
	if a.GrantSHA256 != wantGrant {
		t.Fatalf("grant golden got=%s want=%s", a.GrantSHA256, wantGrant)
	}
	msg, _ := digestBytes(wantGrant)
	wrapper := []byte(bootstrap.EncodeSignature(ed25519.Sign(priv, msg)))
	if got := evidencecas.Digest(wrapper); got != "sha256:c22d99a5beebf2a1b0ee26d75d82bc61f7aaa477422f781604b8149d231c7288" {
		t.Fatalf("signature wrapper golden=%s", got)
	} else if got == evidencecas.Digest(ed25519.Sign(priv, msg)) {
		t.Fatal("signature wrapper was not committed")
	}
}
