package operationtrust

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
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// t5DIntegrationFixture deliberately uses the concrete installed-loader path:
// raw object files, an enrolled SQLite store, local CAS evidence and OpenRuntime.
// It does not substitute a test Runtime, authority or permit implementation.
type t5DIntegrationFixture struct {
	dir, scratch, project, evidence string
	selection                       trustload.LaunchSelection
	policy                          trustverify.ExecutionPolicy
	approver                        ed25519.PrivateKey
	anchor, publisher               ed25519.PrivateKey
	source, target                  trustverify.Subject
	sourceRefs, targetRefs          trustverify.EvidenceRefs
}

func TestT5DConcreteRuntimePrepareAndActionfulPlan(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t)
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatalf("OpenRuntime: %v", err)
	}
	defer runtime.Close()
	stable := runtime.TrustRuntime()
	if stable == nil {
		t.Fatal("concrete C runtime did not compose stable verifier")
	}

	newPrepared, err := PrepareNew(context.Background(), runtime, PrepareNewInput{SourceInput: t5DSelection(f.source, f.sourceRefs), Render: t5DRenderInput(), RendererVersion: "v1"})
	if err != nil {
		t.Fatalf("PrepareNew: %v", err)
	}
	if !newPrepared.ValidFor(stable) || newPrepared.RootLock().Root.Commit != f.source.Commit || len(newPrepared.DependencyLock().Dependencies) != 0 {
		t.Fatalf("new opaque projection is not the verified target pair: %#v", newPrepared.RootLock())
	}
	copyResult := newPrepared.Rendered()
	if len(copyResult.Files) == 0 {
		t.Fatal("new did not render verified native snapshot")
	}
	for path := range copyResult.Files {
		copyResult.Files[path][0] ^= 1
		break
	}
	for path, got := range newPrepared.Rendered().Files {
		if string(got) == string(copyResult.Files[path]) {
			t.Fatal("Rendered exposed mutable backing bytes")
		}
		break
	}

	prepared, err := PrepareUpdate(context.Background(), runtime, PrepareUpdateInput{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs), Render: t5DRenderInput(), RendererVersion: "v1", PreimageSHA256: evidencecas.Digest([]byte("bounded-preimage"))})
	if err != nil {
		t.Fatalf("PrepareUpdate: %v", err)
	}
	if !prepared.ValidFor(stable) || prepared.SourceRootLock().Root.Commit != f.source.Commit || prepared.TargetRootLock().Root.Commit != f.target.Commit || prepared.SourceRootLock().Root.Commit == prepared.TargetRootLock().Root.Commit {
		t.Fatalf("update did not retain distinct verified pairs: source=%#v target=%#v", prepared.SourceRootLock().Root, prepared.TargetRootLock().Root)
	}
	if !prepared.SourceRootLock().TrustProfile.Equal(stable.Binding()) || !prepared.TargetRootLock().TrustProfile.Equal(stable.Binding()) {
		t.Fatal("projected locks escaped concrete runtime binding")
	}

	targetResolution, err := stable.VerifySubject(context.Background(), f.target, f.targetRefs)
	if err != nil {
		t.Fatalf("actual VerifySubject(target): %v", err)
	}
	op, request, staged := t5DActionInputs(t, stable.Binding(), f.source, f.target, runtime.ProjectContext().ProjectID)
	refs := t5DPersistentApproval(t, f, request)
	permits, err := AuthorizeActions(context.Background(), stable, targetResolution, op, []trustverify.ExecutionRequest{request}, []trustverify.ApprovalRefs{refs})
	if err != nil {
		t.Fatalf("AuthorizeActions persistent proof: %v", err)
	}
	plan, err := BuildActionfulUpdatePlan(stable, prepared, op, []trustverify.ExecutionRequest{request}, permits, "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatalf("BuildActionfulUpdatePlan: %v", err)
	}
	if len(plan.Actions) != 1 || len(plan.Requests) != 1 || plan.Source.RootLockSHA256 == plan.Target.RootLockSHA256 {
		t.Fatalf("incomplete actionful plan: %#v", plan)
	}
	if err := RecheckAction(context.Background(), stable, permits[0], request, t5DStaged{staged}); err != nil {
		t.Fatalf("actual RecheckExecution: %v", err)
	}
	staged.ToolBytes = []byte("substituted")
	if err := RecheckAction(context.Background(), stable, permits[0], request, t5DStaged{staged}); err == nil {
		t.Fatal("RecheckAction accepted substituted preimage material")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*trustverify.OperationInputs)
	}{
		{"replace verified source", func(o *trustverify.OperationInputs) {
			o.Subjects = []trustverify.Provider{o.Actions[0].Provider}
		}},
		{"preimage", func(o *trustverify.OperationInputs) { o.PreimageSHA256 = evidencecas.Digest([]byte("other-preimage")) }},
		{"answers", func(o *trustverify.OperationInputs) {
			o.AnswersSHA256 = evidencecas.Digest([]byte("{\\\"other\\\":true}"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := op
			bad.Subjects = append([]trustverify.Provider(nil), op.Subjects...)
			tc.mutate(&bad)
			digest, err := trustverify.ComputeOperationInputsSHA256(bad)
			if err != nil {
				t.Fatalf("mutated operation must remain well-formed: %v", err)
			}
			boundRequest := request
			boundRequest.OperationInputsSHA256 = digest
			boundRequest.RequestSHA256, err = boundRequest.ComputeRequestSHA256()
			if err != nil {
				t.Fatalf("mutated request must remain well-formed: %v", err)
			}
			boundPermits, err := AuthorizeActions(context.Background(), stable, targetResolution, bad, []trustverify.ExecutionRequest{boundRequest}, []trustverify.ApprovalRefs{t5DPersistentApproval(t, f, boundRequest)})
			if err != nil || len(boundPermits) != 1 {
				t.Fatalf("mutated operation authorization = %v, %v", boundPermits, err)
			}
			if plan, err := BuildActionfulUpdatePlan(stable, prepared, bad, []trustverify.ExecutionRequest{boundRequest}, boundPermits, "2026-06-01T00:00:00Z"); err == nil || plan != nil {
				t.Fatalf("preview binding accepted %s: plan=%#v err=%v", tc.name, plan, err)
			}
		})
	}
	t5DAssertEmptyDir(t, f.scratch)
}

func TestT5DConcreteRuntimeRejectsTamperedSelectionBeforeScratch(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t)
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	bad := f.source
	bad.ContractSHA256 = evidencecas.Digest([]byte("forged-contract"))
	if _, err := PrepareNew(context.Background(), runtime, PrepareNewInput{SourceInput: t5DSelection(bad, f.sourceRefs), Render: t5DRenderInput(), RendererVersion: "v1"}); err == nil {
		t.Fatal("forged source contract accepted")
	}
	if _, err := PrepareNew(context.Background(), runtime, PrepareNewInput{SourceInput: append(t5DSelection(f.source, f.sourceRefs)[:len(t5DSelection(f.source, f.sourceRefs))-1], []byte(`,"authority":"forged"}`)...), Render: t5DRenderInput(), RendererVersion: "v1"}); err == nil {
		t.Fatal("open source selection accepted")
	}
	t5DAssertEmptyDir(t, f.scratch)
}

func TestT5DConcreteRuntimeRejectsVerifiedUnsupportedActionsBeforeScratch(t *testing.T) {
	testfixture.RequireTrustStore(t)
	newCases := []struct {
		name, manifest string
	}{
		{"post-create", "hooks:\n  postCreate:\n    - run: echo forbidden\n"},
		{"required-tool", "requires:\n  tools:\n    - name: forbidden-tool\n      version: '1'\n      required: true\n"},
		{"environment-playbook", "environment:\n  playbooks:\n    - name: forbidden-playbook\n      file: setup.yml\n      description: forbidden\n"},
	}
	for _, tc := range newCases {
		t.Run(tc.name, func(t *testing.T) {
			f := t5DNewIntegrationFixture(t, tc.manifest, "")
			runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			if got, err := PrepareNew(context.Background(), runtime, PrepareNewInput{SourceInput: t5DSelection(f.source, f.sourceRefs), Render: t5DRenderInput(), RendererVersion: "v1"}); !errors.Is(err, ErrSourceAdapterUnsupported) || got != nil {
				t.Fatalf("PrepareNew accepted verified %s: %#v, %v", tc.name, got, err)
			}
			t5DAssertEmptyDir(t, f.scratch)
		})
	}
	t.Run("post-update", func(t *testing.T) {
		f := t5DNewIntegrationFixture(t, "", "hooks:\n  postUpdate:\n    - run: echo forbidden\n")
		runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		got, err := PrepareUpdate(context.Background(), runtime, PrepareUpdateInput{SourceInput: t5DSelection(f.source, f.sourceRefs), TargetInput: t5DSelection(f.target, f.targetRefs), Render: t5DRenderInput(), RendererVersion: "v1", PreimageSHA256: evidencecas.Digest([]byte("bounded-preimage"))})
		if !errors.Is(err, ErrSourceAdapterUnsupported) || got != nil {
			t.Fatalf("PrepareUpdate accepted verified postUpdate: %#v, %v", got, err)
		}
		t5DAssertEmptyDir(t, f.scratch)
	})
}

type t5DClock struct{}

func (t5DClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

type t5DStaged struct{ material trustverify.StagedMaterial }

func (s t5DStaged) Stage(context.Context, trustverify.ExecutionRequest) (trustverify.StagedMaterial, error) {
	return s.material, nil
}

func t5DNewIntegrationFixture(t *testing.T, extras ...string) *t5DIntegrationFixture {
	t.Helper()
	sourceExtra, targetExtra := "", ""
	if len(extras) > 0 {
		sourceExtra = extras[0]
	}
	if len(extras) > 1 {
		targetExtra = extras[1]
	}
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-t5d-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &t5DIntegrationFixture{dir: dir, scratch: filepath.Join(dir, "scratch"), project: filepath.Join(dir, "project"), evidence: filepath.Join(dir, "evidence"), anchor: ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901")), publisher: ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012")), approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123"))}
	for _, p := range []string{f.scratch, f.project, f.evidence, filepath.Join(dir, "objects")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sourceContract, source := t5DWriteNativeSource(t, filepath.Join(dir, "objects"), "source", "hello source\n", sourceExtra)
	_, target := t5DWriteNativeSource(t, filepath.Join(dir, "objects"), "target", "hello target\n", targetExtra)
	f.source, f.target = source, target
	evidence := map[string][]byte{}
	put := func(b []byte) string { d := evidencecas.Digest(b); evidence[d] = append([]byte(nil), b...); return d }
	anchorPub, publisherPub := f.anchor.Public().(ed25519.PublicKey), f.publisher.Public().(ed25519.PublicKey)
	rootRef := put([]byte(bootstrap.EncodePublicKey(publisherPub)))
	env := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t5d-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	env.PayloadSHA256, err = env.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(env.PayloadSHA256[7:])
	env.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(f.anchor, payload))))}}
	envRaw, _ := json.Marshal(env)
	envRef := put(envRaw)
	f.sourceRefs = t5DPublisherEvidence(t, evidence, f.publisher, source, "publisher-1")
	f.targetRefs = t5DPublisherEvidence(t, evidence, f.publisher, target, "publisher-1")
	leaf0, leaf1, leaf2 := bootstrap.HashLeaf([]byte(env.PayloadSHA256)), bootstrap.HashLeaf([]byte(f.sourceRefs.StatementCAS)), bootstrap.HashLeaf([]byte(f.targetRefs.StatementCAS))
	left := bootstrap.HashChildren(leaf0, leaf1)
	rootHash := bootstrap.HashChildren(left, leaf2)
	checkpointRef := put(t5DJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: env.AuthorityID, TreeSize: 3, RootHash: "sha256:" + hex.EncodeToString(rootHash[:])}))
	inclusionRef := put(t5DJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf1[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	f.sourceRefs.CheckpointCAS, f.sourceRefs.InclusionProofCAS = checkpointRef, put(t5DJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(leaf0[:]), "sha256:" + hex.EncodeToString(leaf2[:])}}))
	f.targetRefs.CheckpointCAS, f.targetRefs.InclusionProofCAS = checkpointRef, put(t5DJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 2, TreeSize: 3, Hashes: []string{"sha256:" + hex.EncodeToString(left[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: env.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, TreeSize: 3, CheckpointDigest: checkpointRef}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	receiptRef := put(t5DJSON(t, receipt))
	desc := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: env.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: "https://example.test/source", TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	desc.DescriptorSHA256 = desc.ComputedSHA256()
	opRecord := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256}
	opRaw := t5DJSON(t, opRecord)
	prov := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(opRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	prov.ProvisioningSHA256 = prov.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: desc.DescriptorSHA256, ProvisioningSHA256: prov.ProvisioningSHA256, AuthorityID: env.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 3, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	approverPub := f.approver.Public().(ed25519.PublicKey)
	f.policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t5d-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: "https://example.test/source", TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t5d-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t5d", OperationScope: "update", ActionKind: "command", Origin: "https://example.test/source", TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 1000}
	f.policy.PolicySHA256, err = f.policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	descRaw, provRaw, policyRaw := t5DJSON(t, desc), t5DJSON(t, prov), t5DJSON(t, f.policy)
	paths := map[string][]byte{filepath.Join(dir, "descriptor.json"): descRaw, filepath.Join(dir, "provisioning.json"): provRaw, filepath.Join(dir, "operator.json"): opRaw, filepath.Join(dir, "policy.json"): policyRaw, filepath.Join(dir, "state.json"): t5DJSON(t, state)}
	for p, b := range paths {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef}}
	bundleRaw := t5DJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t5d-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: t5DPin(filepath.Join(dir, "descriptor.json"), descRaw), Provisioning: t5DPin(filepath.Join(dir, "provisioning.json"), provRaw), OperatorRecord: t5DPin(filepath.Join(dir, "operator.json"), opRaw), ExecutionPolicy: t5DPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t5d", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: f.project}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: "https://example.test/source", RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: f.evidence, ScratchRoot: f.scratch, OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := t5DJSON(t, install)
	installPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(installPath, installRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.selection = trustload.LaunchSelection{Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: digest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, t5DClock{}, nil, 0)
	}
	if err := trustload.Enroll(context.Background(), f.selection, factory, t5DJSON(t, state), bundleRaw, evidence); err != nil {
		t.Fatalf("Enroll concrete store: %v", err)
	}
	_ = sourceContract
	return f
}

func t5DWriteNativeSource(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: t5d-" + suffix + "\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: label\n    title: Label\n    type: string\n    default: ok\n" + extra)
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+strconvItoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	blob := func(b []byte) string { return add("blob", b) }
	file := blob([]byte(output))
	files := t5DTree(add, []t5DTreeEntry{{mode: "100644", name: "hello.txt.tmpl", oid: file}})
	manifestID, contractID := blob(manifest), blob(contract)
	rootID := t5DTree(add, []t5DTreeEntry{{mode: "40000", name: "files", oid: files}, {mode: "100644", name: "template.contract.json", oid: contractID}, {mode: "100644", name: "template.manifest.yaml", oid: manifestID}})
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor t5d <t5d@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := []trustverify.SourceEntry{{Path: "files", Kind: "directory", Mode: "40000"}, {Path: "files/hello.txt.tmpl", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte(output))}, {Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(contract)}, {Path: "template.manifest.yaml", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(manifest)}}
	treeDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	return contract, trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: commit, Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

type t5DTreeEntry struct{ mode, name, oid string }

func t5DTree(add func(string, []byte) string, entries []t5DTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var raw []byte
	for _, e := range entries {
		b, _ := hex.DecodeString(e.oid)
		raw = append(raw, []byte(e.mode+" "+e.name+"\x00")...)
		raw = append(raw, b...)
	}
	return add("tree", raw)
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func t5DJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func t5DPin(path string, raw []byte) trustload.FilePin {
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}
}

func t5DPublisherEvidence(t *testing.T, store map[string][]byte, key ed25519.PrivateKey, subject trustverify.Subject, issuer string) trustverify.EvidenceRefs {
	t.Helper()
	put := func(b []byte) string { d := evidencecas.Digest(b); store[d] = append([]byte(nil), b...); return d }
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: issuer, Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
	raw := t5DJSON(t, statement)
	statementCAS := put(raw)
	digest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hex.DecodeString(digest[7:])
	signature := put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, hash))))
	return trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signature, KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey))}
}

func t5DSelection(s trustverify.Subject, e trustverify.EvidenceRefs) []byte {
	return []byte(`{"apiVersion":"tplaiter.dev/source-selection-input/v1","subject":{"origin":"` + s.Origin + `","templatePath":"` + s.TemplatePath + `","requestedRef":"` + s.RequestedRef + `","commit":"` + s.Commit + `","treeSHA256":"` + s.TreeSHA256 + `","contractSHA256":"` + s.ContractSHA256 + `"},"evidence":{"format":"` + e.Format + `","statementCAS":"` + e.StatementCAS + `","signatureCAS":"` + e.SignatureCAS + `","keyFingerprint":"` + e.KeyFingerprint + `","checkpointCAS":"` + e.CheckpointCAS + `","inclusionProofCAS":"` + e.InclusionProofCAS + `"},"dependencies":[]}`)
}

func t5DRenderInput() renderref.Input {
	return renderref.Input{Values: renderref.Values(map[string]any{}), Repo: "t5d"}
}

func t5DAssertEmptyDir(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("preparation leaked scratch: %v", entries)
	}
}

func t5DActionInputs(t *testing.T, b bootstrap.ProfileBinding, source, target trustverify.Subject, project string) (trustverify.OperationInputs, trustverify.ExecutionRequest, trustverify.StagedMaterial) {
	t.Helper()
	bd, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, b)
	if err != nil {
		t.Fatal(err)
	}
	content, tool := []byte("t5d-frozen-content"), []byte("t5d-frozen-tool")
	entries := []trustverify.ContentEntry{{Root: "provider", Path: "action.sh", Mode: "100755", ContentSHA256: evidencecas.Digest(content)}}
	closure, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		t.Fatal(err)
	}
	opts := []string{"--fixed"}
	optionsHash, err := trustverify.ComputeToolOptionsSHA256(opts)
	if err != nil {
		t.Fatal(err)
	}
	env := trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Inherit: false, Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}}
	envHash, err := trustverify.ComputeEnvironmentPolicySHA256(env)
	if err != nil {
		t.Fatal(err)
	}
	provider := func(s trustverify.Subject) trustverify.Provider {
		return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
	}
	action := trustverify.Action{ID: "t5d-action", Kind: "command", Phase: "standalone", Argv: []string{"tool.t5d", "--fixed"}, ContentClosureSHA256: closure}
	tl := trustverify.Tool{ID: "tool.t5d", Version: "1", BinarySHA256: evidencecas.Digest(tool), OptionsSHA256: optionsHash}
	material := trustverify.ActionMaterial{Provider: provider(target), Action: action, Tool: tl, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: envHash, TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}
	subjects := []trustverify.Provider{provider(source), provider(target)}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Commit < subjects[j].Commit })
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: project, Scope: "update", PreimageSHA256: evidencecas.Digest([]byte("bounded-preimage")), AnswersSHA256: evidencecas.Digest([]byte("{}")), Subjects: subjects, Actions: []trustverify.ActionMaterial{material}}
	opDigest, err := trustverify.ComputeOperationInputsSHA256(op)
	if err != nil {
		t.Fatal(err)
	}
	req := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: opDigest, ProjectID: project, Scope: "update", Provider: material.Provider, Action: action, Tool: tl, WorkingDirectoryScope: material.WorkingDirectoryScope, EnvironmentPolicySHA256: envHash, TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}
	req.RequestSHA256, err = req.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return op, req, trustverify.StagedMaterial{Operation: op, Request: req, Content: entries, ContentBytes: [][]byte{content}, ToolBytes: tool, ToolOptions: opts, Environment: env}
}

func t5DPersistentApproval(t *testing.T, f *t5DIntegrationFixture, req trustverify.ExecutionRequest) trustverify.ApprovalRefs {
	t.Helper()
	a := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: req.RequestSHA256, ProfileBindingSHA256: req.ProfileBindingSHA256, OperationInputsSHA256: req.OperationInputsSHA256, ProjectID: req.ProjectID, Scope: req.Scope, ApproverID: f.policy.Approvers[0].ID, IdentityClass: f.policy.Approvers[0].IdentityClass, ExecutionPolicySHA256: f.policy.PolicySHA256, Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, KeyFingerprint: f.policy.Approvers[0].KeyFingerprint}
	var err error
	a.GrantSHA256, err = a.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := hex.DecodeString(a.GrantSHA256[7:])
	a.SignatureCAS = evidencecas.Digest([]byte(bootstrap.EncodeSignature(ed25519.Sign(f.approver, grant))))
	raw := t5DJSON(t, a)
	t5DWriteCAS(t, f.evidence, a.SignatureCAS, []byte(bootstrap.EncodeSignature(ed25519.Sign(f.approver, grant))))
	approval := evidencecas.Digest(raw)
	t5DWriteCAS(t, f.evidence, approval, raw)
	return trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: approval}
}

func t5DWriteCAS(t *testing.T, root, digest string, raw []byte) {
	t.Helper()
	hexPart := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(root, "sha256", hexPart[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexPart[2:]), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDeprecatedSnapshotSeparateFromNewCapability(t *testing.T) {
	testfixture.RequireTrustStore(t)
	f := t5DNewIntegrationFixture(t, "  - {group: retired, title: Retired, type: toggle, deprecated: true}\n")
	runtime, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	render := t5DRenderInput()
	render.Values["retired"] = false
	if _, err := PrepareNew(context.Background(), runtime, PrepareNewInput{SourceInput: t5DSelection(f.source, f.sourceRefs), Render: render, RendererVersion: "v1"}); err == nil {
		t.Fatal("fresh native preparation accepted fake retained map")
	}
	snapshot, err := PrepareSnapshot(context.Background(), runtime, PrepareSnapshotInput{SourceInput: t5DSelection(f.source, f.sourceRefs), Render: render, RendererVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.ValidFor(runtime.TrustRuntime()) || snapshot.RootLock().Root.Commit != f.source.Commit {
		t.Fatal("snapshot escaped signed source")
	}
	if _, ok := any(snapshot).(*PreparedNew); ok {
		t.Fatal("snapshot convertible to fresh New")
	}
	copy := snapshot.Rendered()
	copy.Resolved.Values["retired"] = true
	if snapshot.Rendered().Resolved.Values["retired"] != false {
		t.Fatal("snapshot aliases caller")
	}
}
