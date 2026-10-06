package trustverify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// This fixture contains the raw stable bootstrap chain and a second proof for
// the publisher statement.  It exercises NewRuntime and VerifySubject only
// through their public inputs; no Authority is injected or fabricated.
type runtimeFixture struct {
	store   map[string][]byte
	ext     bootstrap.ProvisionedSnapshot
	bundle  bootstrap.Bundle
	policy  ExecutionPolicySnapshot
	project ProjectContext
	objects GitObjectReader
	subject Subject
	refs    EvidenceRefs
	now     time.Time
}
type runtimeStore map[string][]byte

func (s runtimeStore) Read(_ context.Context, d string) ([]byte, error) {
	b, ok := s[d]
	if !ok {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), b...), nil
}

type countingEvidenceReader struct {
	reader evidencecas.Reader
	reads  int
}

func (r *countingEvidenceReader) Read(ctx context.Context, digest string) ([]byte, error) {
	r.reads++
	return r.reader.Read(ctx, digest)
}

type runtimeExternal struct {
	f     *runtimeFixture
	calls int
}

func (r *runtimeExternal) Load(context.Context) (bootstrap.ProvisionedSnapshot, error) {
	r.calls++
	return r.f.ext, nil
}

type runtimeBundle struct {
	f     *runtimeFixture
	calls int
}

func (r *runtimeBundle) Load(context.Context) (bootstrap.Bundle, error) {
	r.calls++
	return r.f.bundle, nil
}

type runtimePolicy struct {
	f     *runtimeFixture
	calls int
}

func (r *runtimePolicy) Load(context.Context) (ExecutionPolicySnapshot, error) {
	r.calls++
	return r.f.policy, nil
}

type runtimeProject struct {
	f     *runtimeFixture
	calls int
}

func (r *runtimeProject) Load(context.Context) (ProjectContext, error) {
	r.calls++
	return r.f.project, nil
}

type runtimeClock struct{ fixture *runtimeFixture }

func (c runtimeClock) Now() time.Time { return c.fixture.now }

func runtimePut(s map[string][]byte, b []byte) string {
	d := evidencecas.Digest(b)
	s[d] = append([]byte(nil), b...)
	return d
}
func runtimeHash(h bootstrap.MerkleHash) string { return "sha256:" + hex.EncodeToString(h[:]) }
func runtimeKey(label string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(h[:])
}

func runtimeRawDigest(t *testing.T, d string) []byte {
	t.Helper()
	b, e := hex.DecodeString(d[len("sha256:"):])
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	objects, subject := fixture(20, []byte("{\"apiVersion\":\"fixture\"}\n"))
	store := map[string][]byte{}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	anchor, publisher := runtimeKey("runtime-anchor"), runtimeKey("runtime-publisher")
	anchorPub, publisherPub := anchor.Public().(ed25519.PublicKey), publisher.Public().(ed25519.PublicKey)
	publisherRef := runtimePut(store, []byte(bootstrap.EncodePublicKey(publisherPub)))
	envelope := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "runtime-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: publisherRef, Issuer: "publisher", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	var err error
	envelope.PayloadSHA256, err = envelope.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	anchorSig := runtimePut(store, []byte(bootstrap.EncodeSignature(ed25519.Sign(anchor, runtimeRawDigest(t, envelope.PayloadSHA256)))))
	envelope.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: anchorSig}}

	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: "publisher", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: subject.Origin, TemplatePath: subject.TemplatePath, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256}}
	statementRaw, _ := json.Marshal(statement)
	statementCAS := runtimePut(store, statementRaw)
	statementDigest, err := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	signatureCAS := runtimePut(store, []byte(bootstrap.EncodeSignature(ed25519.Sign(publisher, runtimeRawDigest(t, statementDigest)))))

	// One checkpoint binds both the envelope payload (leaf zero) and the exact
	// statement CAS digest string (leaf one). The two proofs are deliberately
	// different, proving that envelope inclusion cannot stand in for artifact inclusion.
	envelopeLeaf, statementLeaf := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256)), bootstrap.HashLeaf([]byte(statementCAS))
	checkpointRaw, _ := json.Marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: envelope.AuthorityID, TreeSize: 2, RootHash: runtimeHash(bootstrap.HashChildren(envelopeLeaf, statementLeaf))})
	checkpointCAS := runtimePut(store, checkpointRaw)
	envelopeProofRaw, _ := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 2, Hashes: []string{runtimeHash(statementLeaf)}})
	envelopeProofCAS := runtimePut(store, envelopeProofRaw)
	statementProofRaw, _ := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 2, Hashes: []string{runtimeHash(envelopeLeaf)}})
	statementProofCAS := runtimePut(store, statementProofRaw)
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
	provisioning := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: descriptor.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest([]byte("fixture-auth")), EvidenceClass: bootstrap.EvidenceProduction}
	provisioning.ProvisioningSHA256 = provisioning.ComputedSHA256()
	provisioningRaw, _ := json.Marshal(provisioning)
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: descriptor.DescriptorSHA256, ProvisioningSHA256: provisioning.ProvisioningSHA256, AuthorityID: envelope.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 2, CheckpointDigest: checkpointCAS}
	state.StateSHA256 = state.ComputedSHA256()
	stateRaw, _ := json.Marshal(state)
	policy := ExecutionPolicy{APIVersion: ExecutionPolicyAPIVersion, PolicyID: "runtime-policy", Profile: "oss", MinimumProfile: "oss", Validity: Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []Principal{{ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []IssuerPrincipal{{Issuer: "publisher", PrincipalID: "principal:publisher"}}, SourceRules: []SourceRule{{PolicyOrigin: statement.PolicyOrigin, Issuer: statement.Issuer, Origin: statement.Subject.Origin, TemplatePath: statement.Subject.TemplatePath, Predicate: statement.Predicate, Format: "tplaiter-publisher-statement-v1"}}, Approvers: []Approver{}, AllowInvocationHuman: false, MaxTimeoutMillis: 1000}
	var policyErr error
	policy.PolicySHA256, policyErr = policy.ComputePolicySHA256()
	if policyErr != nil {
		t.Fatal(policyErr)
	}
	policyRaw, _ := json.Marshal(policy)
	return &runtimeFixture{store: store, ext: bootstrap.ProvisionedSnapshot{DescriptorJSON: descriptorRaw, ProvisioningJSON: provisioningRaw, ExpectedDescriptorSHA256: descriptor.DescriptorSHA256, ExpectedProvisioningSHA256: provisioning.ProvisioningSHA256, OSSStateJSON: stateRaw, ExpectedOSSStateSHA256: state.StateSHA256, InitialOSSStateSHA256: state.StateSHA256}, bundle: bootstrap.Bundle{Envelope: rawEnvelope, Receipt: rawReceipt, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: checkpointCAS, InclusionProofCAS: envelopeProofCAS}}, policy: ExecutionPolicySnapshot{PolicyJSON: policyRaw, ExpectedPolicySHA256: policy.PolicySHA256}, project: ProjectContext{ProjectID: "project-fixture", SubmitterPrincipalID: "principal:submitter", MinimumProfile: "oss"}, objects: objects, subject: subject, refs: EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: statementCAS, SignatureCAS: signatureCAS, KeyFingerprint: bootstrap.Fingerprint(publisherPub), CheckpointCAS: checkpointCAS, InclusionProofCAS: statementProofCAS}, now: now}
}

func runtimeOptions(f *runtimeFixture, ext *runtimeExternal, pol *runtimePolicy, bundle *runtimeBundle, project *runtimeProject) StableOptions {
	return StableOptions{Profile: bootstrap.ProfileOSS, Project: project, Policy: pol, External: ext, Bundle: bundle, Evidence: runtimeStore(f.store), Objects: f.objects, Clock: runtimeClock{fixture: f}}
}

func TestRuntimeVerifySubjectActualStableFixture(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	wantBinding := bootstrap.ProfileBinding{APIVersion: bootstrap.ProfileBindingAPIVersion, ID: bootstrap.ProfileOSS, DefinitionVersion: 1, ConfigSHA256: "sha256:e77433de59889de5d10f63485b36456a2f09f2d0a841e8f3042092d4b8fa3638", PolicySHA256: "sha256:7f90655cfefcb31e9f7a4b3ffe7b86339aeb1c976e3d670c5946efd89c3cba51", AuthoritySHA256: "sha256:37a6cd6fab2e132d89c5d54d3bcc789d09025bd5e6f86df794c23e0fe5f1c201", Assurance: bootstrap.PublisherVerified, EvidenceClass: bootstrap.EvidenceProduction}
	if !r.Binding().Equal(wantBinding) {
		t.Fatalf("runtime binding = %+v", r.Binding())
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if resolution == nil || !resolution.ValidFor(r, r.Binding()) || resolution.Subject() != f.subject {
		t.Fatal("nonzero immutable instance-bound resolution was not returned")
	}
	if resolution.publisherIssuer != "publisher" || resolution.publisherPrincipalID != "principal:publisher" || resolution.rule.TemplatePath != "." {
		t.Fatal("exact source rule/principal mapping was not retained")
	}
	if ext.calls < 3 || pol.calls < 3 || bundle.calls < 3 || project.calls < 3 {
		t.Fatalf("fresh reads: ext=%d policy=%d bundle=%d project=%d", ext.calls, pol.calls, bundle.calls, project.calls)
	}
}

func TestRuntimeRejectsArtifactProofAndFreshProjectPolicyChanges(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	bad := f.refs
	bad.InclusionProofCAS = f.bundle.Transparency.InclusionProofCAS
	if _, err = r.VerifySubject(context.Background(), f.subject, bad); err == nil {
		t.Fatal("envelope inclusion proof was accepted as statement artifact proof")
	}
	bad = f.refs
	bad.Format = "unknown-proof/v1"
	if _, err = r.VerifySubject(context.Background(), f.subject, bad); err == nil {
		t.Fatal("unknown evidence format accepted")
	}
	f.project.MinimumProfile = "organization"
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
		t.Fatal("fresh changed project minimum was accepted")
	}
	f.project.MinimumProfile = "oss"
	f.project.SubmitterPrincipalID = "principal:publisher"
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
		t.Fatal("fresh changed submitter principal was accepted")
	}
	f.project.SubmitterPrincipalID = "principal:submitter"
	var changed ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &changed); err != nil {
		t.Fatal(err)
	}
	changed.PolicyID = "changed-runtime-policy"
	changed.PolicySHA256, err = changed.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy.PolicyJSON, _ = json.Marshal(changed)
	f.policy.ExpectedPolicySHA256 = changed.PolicySHA256
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
		t.Fatal("fresh changed execution policy was accepted")
	}
	f.now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
		t.Fatal("expired policy was accepted on fresh subject load")
	}
}

func TestRuntimeRejectsActualSourceMismatchAndCanceledContext(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	wrong := f.subject
	wrong.TreeSHA256 = evidencecas.Digest([]byte("wrong"))
	if _, err = r.VerifySubject(context.Background(), wrong, f.refs); err == nil {
		t.Fatal("caller source mismatch was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.VerifySubject(ctx, f.subject, f.refs); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}

type unsafeReaderError struct{}

func (unsafeReaderError) Error() string { return "UNSAFE-READER-PATH:/private/credential" }

type failingProject struct{}

func (failingProject) Load(context.Context) (ProjectContext, error) {
	return ProjectContext{}, unsafeReaderError{}
}

func TestRuntimeDiagnosticsContainOnlySafeCode(t *testing.T) {
	f := newRuntimeFixture(t)
	_, err := NewRuntime(context.Background(), StableOptions{Profile: bootstrap.ProfileOSS, Project: failingProject{}, Policy: &runtimePolicy{f: f}, External: &runtimeExternal{f: f}, Bundle: &runtimeBundle{f: f}, Evidence: runtimeStore(f.store), Objects: f.objects, Clock: runtimeClock{fixture: f}})
	if err == nil || err.Error() != string(TrustRuntimeInvalid) || errors.Unwrap(err) != nil {
		t.Fatalf("unsafe diagnostic exposure: %v unwrap=%v", err, errors.Unwrap(err))
	}
	var unsafe unsafeReaderError
	if errors.As(err, &unsafe) {
		t.Fatal("unsafe adapter error remained inspectable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewRuntime(ctx, runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity lost: %v", err)
	}
}

func TestResolutionBindingEvidenceAndRuntimeIsolation(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	if (&VerifiedResolution{}).ValidFor(r, r.Binding()) || !resolution.ValidFor(r, r.Binding()) {
		t.Fatal("zero or valid resolution identity failure")
	}
	other, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if resolution.ValidFor(other, other.Binding()) {
		t.Fatal("resolution accepted by another runtime")
	}
	changed := r.Binding()
	changed.ConfigSHA256 = evidencecas.Digest([]byte("changed"))
	if resolution.ValidFor(r, changed) {
		t.Fatal("altered binding accepted")
	}
	e := resolution.Evidence()
	e.StatementCAS = evidencecas.Digest([]byte("changed"))
	if resolution.Evidence() != f.refs {
		t.Fatal("evidence accessor altered retained refs")
	}
	if resolution.Subject() != f.subject {
		t.Fatal("subject accessor altered retained source")
	}
}

type mutationStore struct {
	runtimeStore
	target string
	armed  bool
	mutate func()
}

func (s *mutationStore) Read(ctx context.Context, d string) ([]byte, error) {
	b, err := s.runtimeStore.Read(ctx, d)
	if s.armed && d == s.target {
		s.armed = false
		s.mutate()
	}
	return b, err
}

func TestRuntimeRejectsPostProofFreshBindingMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *runtimeFixture)
	}{
		{"project", func(_ *testing.T, f *runtimeFixture) { f.project.ProjectID = "changed-project" }},
		{"policy", func(t *testing.T, f *runtimeFixture) {
			var p ExecutionPolicy
			if err := json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
				t.Fatal(err)
			}
			p.PolicyID = "post-proof-policy"
			var err error
			p.PolicySHA256, err = p.ComputePolicySHA256()
			if err != nil {
				t.Fatal(err)
			}
			f.policy.PolicyJSON, _ = json.Marshal(p)
			f.policy.ExpectedPolicySHA256 = p.PolicySHA256
		}},
		{"bundle-malformed", func(_ *testing.T, f *runtimeFixture) { f.bundle.Receipt = []byte("{}") }},
		{"external-repinned-descriptor", mutateDescriptorRepin},
		{"receipt-checkpoint-state", mutateReceiptCheckpointState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRuntimeFixture(t)
			ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
			s := &mutationStore{runtimeStore: runtimeStore(f.store), target: f.refs.StatementCAS}
			o := runtimeOptions(f, ext, pol, bundle, project)
			o.Evidence = s
			r, err := NewRuntime(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			s.armed = true
			s.mutate = func() { tc.mutate(t, f) }
			if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
				t.Fatal("post-proof mutation minted resolution")
			}
		})
	}
}

func mutateDescriptorRepin(t *testing.T, f *runtimeFixture) {
	var d bootstrap.DescriptorDocument
	if err := json.Unmarshal(f.ext.DescriptorJSON, &d); err != nil {
		t.Fatal(err)
	}
	d.AllowedPolicyOrigins = append(d.AllowedPolicyOrigins, "https://example.test/unused-policy")
	d.PublisherScopes = append(d.PublisherScopes, bootstrap.PublisherScope{PolicyOrigin: "https://example.test/unused-policy", Issuer: "publisher", SourceOrigin: "https://example.test/unused-source", TemplatePath: "unused", Predicate: "https://example.test/unused-predicate", Usage: "template-source"})
	d.DescriptorSHA256 = d.ComputedSHA256()
	dRaw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var p bootstrap.ProvisioningRecord
	if err = json.Unmarshal(f.ext.ProvisioningJSON, &p); err != nil {
		t.Fatal(err)
	}
	p.DescriptorSHA256 = d.DescriptorSHA256
	p.ProvisioningSHA256 = p.ComputedSHA256()
	pRaw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var state bootstrap.OSSAcceptedState
	if err = json.Unmarshal(f.ext.OSSStateJSON, &state); err != nil {
		t.Fatal(err)
	}
	state.DescriptorSHA256, state.ProvisioningSHA256 = d.DescriptorSHA256, p.ProvisioningSHA256
	state.StateSHA256 = state.ComputedSHA256()
	stateRaw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	f.ext = bootstrap.ProvisionedSnapshot{DescriptorJSON: dRaw, ProvisioningJSON: pRaw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256, OSSStateJSON: stateRaw, ExpectedOSSStateSHA256: state.StateSHA256, InitialOSSStateSHA256: state.StateSHA256}
}

func mutateReceiptCheckpointState(t *testing.T, f *runtimeFixture) {
	var envelope bootstrap.Envelope
	if err := json.Unmarshal(f.bundle.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	leaf, extra := bootstrap.HashLeaf([]byte(envelope.PayloadSHA256)), bootstrap.HashLeaf([]byte("valid-extra-leaf"))
	checkpointRaw, err := json.Marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: envelope.AuthorityID, TreeSize: 2, RootHash: runtimeHash(bootstrap.HashChildren(leaf, extra))})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := runtimePut(f.store, checkpointRaw)
	proofRaw, err := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 2, Hashes: []string{runtimeHash(extra)}})
	if err != nil {
		t.Fatal(err)
	}
	proof := runtimePut(f.store, proofRaw)
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: envelope.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: envelope.PayloadSHA256, RevocationEpoch: 0, TreeSize: 2, CheckpointDigest: checkpoint}
	receipt.ReceiptDigest, err = receipt.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	f.bundle.Receipt, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.bundle.Transparency = bootstrap.TransparencyEvidence{CheckpointCAS: checkpoint, InclusionProofCAS: proof}
	var state bootstrap.OSSAcceptedState
	if err = json.Unmarshal(f.ext.OSSStateJSON, &state); err != nil {
		t.Fatal(err)
	}
	state.ReceiptDigest, state.TreeSize, state.CheckpointDigest = receipt.ReceiptDigest, receipt.TreeSize, checkpoint
	state.StateSHA256 = state.ComputedSHA256()
	f.ext.OSSStateJSON, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	f.ext.ExpectedOSSStateSHA256 = state.StateSHA256
	f.ext.InitialOSSStateSHA256 = state.StateSHA256
}

func TestRuntimePropagatesCancellationDuringProofRead(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	ctx, cancel := context.WithCancel(context.Background())
	s := &mutationStore{runtimeStore: runtimeStore(f.store), target: f.refs.StatementCAS, armed: true, mutate: cancel}
	o := runtimeOptions(f, ext, pol, bundle, project)
	o.Evidence = s
	r, err := NewRuntime(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifySubject(ctx, f.subject, f.refs); !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flow cancellation=%v", err)
	}
}

func TestRuntimeRequiresExactIssuerPrincipalMapping(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	var p ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	// A second, sorted, distinct tuple is permitted when it identifies a
	// different source. The selected tuple remains exact and retains its mapped
	// principal, rather than depending on policy slice position.
	other := p.SourceRules[0]
	other.Origin, other.TemplatePath, other.Predicate = "https://example.test/other-source", "other", "https://example.test/other-predicate"
	p.SourceRules = []SourceRule{other, p.SourceRules[0]}
	var hashErr error
	p.PolicySHA256, hashErr = p.ComputePolicySHA256()
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	f.policy.PolicyJSON, _ = json.Marshal(p)
	f.policy.ExpectedPolicySHA256 = p.PolicySHA256
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil || resolution.publisherPrincipalID != "principal:publisher" || resolution.rule != p.SourceRules[1] {
		t.Fatalf("exact multi-tuple selection: resolution=%#v err=%v", resolution, err)
	}
	// A coherent statement with a different issuer/predicate cannot choose the
	// other tuple; it must match the selected policy tuple exactly.
	badStatement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: p.SourceRules[1].PolicyOrigin, Issuer: "other-publisher", Predicate: "https://example.test/other-predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath, Commit: f.subject.Commit, TreeSHA256: f.subject.TreeSHA256, ContractSHA256: f.subject.ContractSHA256}}
	raw, e := json.Marshal(badStatement)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, badStatement)
	if e != nil {
		t.Fatal(e)
	}
	badRefs := f.refs
	badRefs.StatementCAS = runtimePut(f.store, raw)
	badRefs.SignatureCAS = runtimePut(f.store, []byte(bootstrap.EncodeSignature(ed25519.Sign(runtimeKey("runtime-publisher"), runtimeRawDigest(t, digest)))))
	if _, err = r.VerifySubject(context.Background(), f.subject, badRefs); err == nil {
		t.Fatal("mismatched issuer/predicate statement accepted")
	}
	// Equal locator tuples are ambiguous because EvidenceRefs has no rule
	// selector. matchingRule explicitly fails closed instead of taking slice[0].
	ambiguous := p.SourceRules[1]
	ambiguous.Predicate = "https://example.test/predicate-z"
	p.SourceRules = []SourceRule{other, p.SourceRules[1], ambiguous}
	p.PolicySHA256, hashErr = p.ComputePolicySHA256()
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	f.policy.PolicyJSON, _ = json.Marshal(p)
	f.policy.ExpectedPolicySHA256 = p.PolicySHA256
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err == nil {
		t.Fatal("ambiguous source locator accepted")
	}
}

type protectedFixture struct{ snapshot bootstrap.ProtectedSnapshot }

func (p protectedFixture) CheckProtection(context.Context) error { return nil }
func (p protectedFixture) Snapshot(context.Context) (bootstrap.ProtectedSnapshot, error) {
	return p.snapshot, nil
}

func TestOrganizationRuntimeAndDevelopmentResolutionAreDistinct(t *testing.T) {
	f := newRuntimeFixture(t)
	var d bootstrap.DescriptorDocument
	if err := json.Unmarshal(f.ext.DescriptorJSON, &d); err != nil {
		t.Fatal(err)
	}
	d.Profile = bootstrap.ProfileOrganization
	d.DescriptorSHA256 = d.ComputedSHA256()
	dRaw, _ := json.Marshal(d)
	var p bootstrap.ProvisioningRecord
	if err := json.Unmarshal(f.ext.ProvisioningJSON, &p); err != nil {
		t.Fatal(err)
	}
	p.DescriptorSHA256 = d.DescriptorSHA256
	p.ProvisioningSHA256 = p.ComputedSHA256()
	pRaw, _ := json.Marshal(p)
	var policy ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Profile, policy.MinimumProfile = "organization", "organization"
	policyHash, err := policy.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicySHA256 = policyHash
	policyRaw, _ := json.Marshal(policy)
	f.ext = bootstrap.ProvisionedSnapshot{DescriptorJSON: dRaw, ProvisioningJSON: pRaw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256}
	f.policy = ExecutionPolicySnapshot{PolicyJSON: policyRaw, ExpectedPolicySHA256: policy.PolicySHA256}
	f.project.MinimumProfile = "organization"
	protected := protectedFixture{snapshot: bootstrap.ProtectedSnapshot{Envelope: f.bundle.Envelope, Receipt: f.bundle.Receipt, Transparency: f.bundle.Transparency, BackendID: "synthetic-protected", EvidenceClass: bootstrap.EvidenceProduction}}
	r, err := NewRuntime(context.Background(), StableOptions{Profile: bootstrap.ProfileOrganization, Project: &runtimeProject{f: f}, Policy: &runtimePolicy{f: f}, External: &runtimeExternal{f: f}, Protected: protected, Evidence: runtimeStore(f.store), Objects: f.objects, Clock: runtimeClock{fixture: f}})
	if err != nil {
		t.Fatalf("organization runtime: %v", err)
	}
	if _, err = r.VerifySubject(context.Background(), f.subject, f.refs); err != nil {
		t.Fatalf("organization subject: %v", err)
	}

	// Development accepts an explicit unsigned envelope with its own one-leaf
	// transparency proof and cannot become a stable resolution.
	var e bootstrap.Envelope
	if err := json.Unmarshal(f.bundle.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	e.Signatures = []bootstrap.Signature{}
	raw, _ := json.Marshal(e)
	leaf := bootstrap.HashLeaf([]byte(e.PayloadSHA256))
	cpRaw, _ := json.Marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: e.AuthorityID, TreeSize: 1, RootHash: runtimeHash(leaf)})
	cp := runtimePut(f.store, cpRaw)
	proofRaw, _ := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 1, Hashes: []string{}})
	proof := runtimePut(f.store, proofRaw)
	dr, err := NewDevelopmentRuntime(context.Background(), DevelopmentOptions{Objects: f.objects, Evidence: runtimeStore(f.store), Clock: runtimeClock{fixture: f}, Inputs: bootstrap.DevelopmentInputs{Envelope: raw, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: cp, InclusionProofCAS: proof}}})
	if err != nil {
		t.Fatalf("development runtime: %v", err)
	}
	dres, err := dr.VerifySubject(context.Background(), f.subject)
	if err != nil {
		t.Fatal(err)
	}
	if !dres.ValidFor(dr) || !dres.Diagnostic().ValidFor(dr) || dres.Subject() != f.subject {
		t.Fatal("development resolution diagnostic identity")
	}
	if (&DevelopmentResolution{}).ValidFor(dr) {
		t.Fatal("zero development resolution accepted")
	}
}

type acceptHuman struct{ calls int }

func (h *acceptHuman) Review(_ context.Context, _ HumanReview) (bool, error) {
	h.calls++
	return true, nil
}

type cancelHuman struct{ cancel context.CancelFunc }

func (h cancelHuman) Review(context.Context, HumanReview) (bool, error) { h.cancel(); return true, nil }

type stagedFixture struct{ material StagedMaterial }

func (s stagedFixture) Stage(_ context.Context, _ ExecutionRequest) (StagedMaterial, error) {
	return s.material, nil
}

func permitPolicy(t *testing.T, f *runtimeFixture, profile, minimum, principal, id string, key ed25519.PrivateKey, human bool) {
	t.Helper()
	var p ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	p.Profile, p.MinimumProfile, p.AllowInvocationHuman = profile, minimum, human
	if principal != "" {
		found := false
		for _, x := range p.Principals {
			if x.ID == principal {
				found = true
			}
		}
		if !found {
			p.Principals = append(p.Principals, Principal{ID: principal})
			sort.Slice(p.Principals, func(i, j int) bool { return p.Principals[i].ID < p.Principals[j].ID })
		}
		pub := key.Public().(ed25519.PublicKey)
		p.Approvers = []Approver{{ID: id, PrincipalID: principal, IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(pub), PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Validity: Validity{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}, Scopes: []ApprovalScope{{ProjectID: f.project.ProjectID, OperationScope: "run", ActionKind: "command", Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath}}}}
	} else {
		p.Approvers = []Approver{}
	}
	var err error
	p.PolicySHA256, err = p.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy.PolicyJSON, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.ExpectedPolicySHA256 = p.PolicySHA256
}

func permitInputs(t *testing.T, binding bootstrap.ProfileBinding, subject Subject, project string) (OperationInputs, ExecutionRequest, StagedMaterial) {
	t.Helper()
	bd, err := runtimeBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	contentBytes, toolBytes := []byte("frozen-content"), []byte("frozen-tool")
	entries := []ContentEntry{{Root: "provider", Path: "run.sh", Mode: "100755", ContentSHA256: evidencecas.Digest(contentBytes)}}
	closure, err := ComputeContentClosureSHA256(entries)
	if err != nil {
		t.Fatal(err)
	}
	options := []string{"--exact"}
	od, err := ComputeToolOptionsSHA256(options)
	if err != nil {
		t.Fatal(err)
	}
	env := EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Inherit: false, Variables: []EnvironmentVariable{{Name: "LANG", Value: "C"}}}
	ed, err := ComputeEnvironmentPolicySHA256(env)
	if err != nil {
		t.Fatal(err)
	}
	provider := subjectProvider(subject)
	action := Action{ID: "action.test", Kind: "command", Phase: "standalone", Shell: false, Argv: []string{"tool.test", "--exact"}, ContentClosureSHA256: closure}
	tool := Tool{ID: "tool.test", Version: "1", BinarySHA256: evidencecas.Digest(toolBytes), OptionsSHA256: od}
	op := OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: project, Scope: "run", PreimageSHA256: evidencecas.Digest([]byte("preimage")), AnswersSHA256: evidencecas.Digest([]byte("answers")), Subjects: []Provider{provider}, Actions: []ActionMaterial{{Provider: provider, Action: action, Tool: tool, WorkingDirectoryScope: WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: ed, TimeoutMillis: 100, Migration: Migration{Kind: "none"}}}}
	odig, err := ComputeOperationInputsSHA256(op)
	if err != nil {
		t.Fatal(err)
	}
	req := ExecutionRequest{APIVersion: ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: odig, ProjectID: project, Scope: "run", Provider: provider, Action: action, Tool: tool, WorkingDirectoryScope: WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: ed, TimeoutMillis: 100, Migration: Migration{Kind: "none"}}
	req.RequestSHA256, err = req.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return op, req, StagedMaterial{Operation: cloneOperation(op), Request: cloneRequest(req), Content: entries, ContentBytes: [][]byte{contentBytes}, ToolBytes: toolBytes, ToolOptions: options, Environment: env}
}

func persistentRefs(t *testing.T, f *runtimeFixture, p *ExecutionPolicy, req ExecutionRequest, key ed25519.PrivateKey) ApprovalRefs {
	t.Helper()
	a := ExecutionApproval{APIVersion: ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: req.RequestSHA256, ProfileBindingSHA256: req.ProfileBindingSHA256, OperationInputsSHA256: req.OperationInputsSHA256, ProjectID: req.ProjectID, Scope: req.Scope, ApproverID: p.Approvers[0].ID, IdentityClass: p.Approvers[0].IdentityClass, ExecutionPolicySHA256: p.PolicySHA256, Validity: Validity{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}, KeyFingerprint: p.Approvers[0].KeyFingerprint}
	var err error
	a.GrantSHA256, err = a.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	msg := runtimeRawDigest(t, a.GrantSHA256)
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(key, msg)))
	a.SignatureCAS = runtimePut(f.store, sig)
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: runtimePut(f.store, raw)}
}

func TestExecutionPermitExactOperationAndStagedBytes(t *testing.T) {
	f := newRuntimeFixture(t)
	approver := runtimeKey("permit-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", approver, false)
	r, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	// Independently recorded canonical preimage vectors pin the complete
	// operation, request, and staged content framing used by this permit.
	if req.RequestSHA256 != "sha256:203318d7d5bb1957cfc6c11c1d7691d616a8592880651b21561321e0dcb4a8d3" || req.OperationInputsSHA256 != "sha256:2687daf9eea4587fd1b713d0e8f869870d445a0639b5e8e74ca669dd13ccfc03" || req.Action.ContentClosureSHA256 != "sha256:2fed58b9da06bfd83a1a9184c1b8cfa6ceeb819bec2c9d1c308b3d42f51de472" {
		t.Fatalf("unexpected T3-D digest vectors request=%s operation=%s closure=%s", req.RequestSHA256, req.OperationInputsSHA256, req.Action.ContentClosureSHA256)
	}
	var policy ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	refs := persistentRefs(t, f, &policy, req, approver)
	permit, err := r.Authorize(context.Background(), resolution, op, req, refs)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := permit.Summary(); got.RequestSHA256 != req.RequestSHA256 || got.OperationInputsSHA256 != req.OperationInputsSHA256 {
		t.Fatalf("summary=%+v", got)
	}
	op.Actions[0].Action.Argv = append([]string(nil), op.Actions[0].Action.Argv...)
	op.Actions[0].Action.Argv[1] = "mutated-after-mint"
	if _, err := r.Authorize(context.Background(), permit.resolution, stage.Operation, stage.Request, refs); err != nil {
		t.Fatalf("direct reauthorization of staged material: %v", err)
	}
	if err := r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err != nil {
		t.Fatalf("exact staged recheck: %v", err)
	}
	stage.ToolBytes = []byte("swapped-tool")
	if err := r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err == nil {
		t.Fatal("staged tool substitution accepted")
	}
	stage.ToolBytes = []byte("frozen-tool")
	stage.ContentBytes[0] = []byte("swapped-content")
	if err := r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err == nil {
		t.Fatal("staged content substitution accepted")
	}
	bad := req
	bad.TimeoutMillis = 101
	bad.RequestSHA256, _ = bad.ComputeRequestSHA256()
	if _, err := r.Authorize(context.Background(), resolution, cloneOperation(permit.operation), bad, refs); err == nil {
		t.Fatal("request without exact operation approval accepted")
	}
}

func TestRuntimePersistentApprovalReferenceIsPermitBound(t *testing.T) {
	f := newRuntimeFixture(t)
	approver := runtimeKey("projection-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", approver, false)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	var policy ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	refs := persistentRefs(t, f, &policy, req, approver)
	permit, err := r.Authorize(context.Background(), resolution, op, req, refs)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := f.store[refs.ApprovalCAS]
	if !ok {
		t.Fatal("persistent approval bytes missing")
	}
	approval, err := DecodeExecutionApproval(raw)
	if err != nil {
		t.Fatal(err)
	}
	const wantGrant = "sha256:2cd45d04ad92b9665e640c9ea2906c7e81591f91f4c7da9dd208aaf8f2c24330"
	const wantApprovalCAS = "sha256:60652815467ea9592d3d0e3355d79d4865ff2b0d65ba15a6d00f90df19b49018"
	if approval.GrantSHA256 != wantGrant || refs.ApprovalCAS != wantApprovalCAS {
		t.Fatalf("projection golden grant=%s approvalCAS=%s", approval.GrantSHA256, refs.ApprovalCAS)
	}
	counted := &countingEvidenceReader{reader: runtimeStore(f.store)}
	r.options.Evidence = counted
	extBefore, polBefore, bundleBefore, projectBefore := ext.calls, pol.calls, bundle.calls, project.calls
	ref, err := r.PersistentApprovalReference(permit)
	if err != nil {
		t.Fatal(err)
	}
	if ref != (PersistentApprovalReference{RequestSHA256: req.RequestSHA256, GrantSHA256: wantGrant, ApprovalCAS: wantApprovalCAS}) {
		t.Fatalf("persistent approval reference=%+v", ref)
	}
	if counted.reads != 0 || ext.calls != extBefore || pol.calls != polBefore || bundle.calls != bundleBefore || project.calls != projectBefore {
		t.Fatalf("projection performed I/O: evidence=%d ext=%d policy=%d bundle=%d project=%d", counted.reads, ext.calls-extBefore, pol.calls-polBefore, bundle.calls-bundleBefore, project.calls-projectBefore)
	}
	ref.GrantSHA256 = evidencecas.Digest([]byte("caller-mutation"))
	gotAgain, err := r.PersistentApprovalReference(permit)
	if err != nil || gotAgain.GrantSHA256 != wantGrant {
		t.Fatalf("returned value mutation changed permit reference: ref=%+v err=%v", gotAgain, err)
	}
	for name, forged := range map[string]*ExecutionPermit{
		"zero":        {},
		"empty-grant": func() *ExecutionPermit { p := *permit; p.grantSHA256 = ""; return &p }(),
		"human-kind":  func() *ExecutionPermit { p := *permit; p.approval.Kind = "human"; return &p }(),
		"expired":     func() *ExecutionPermit { p := *permit; p.expires = f.now; return &p }(),
		"binding": func() *ExecutionPermit {
			p := *permit
			p.binding.ConfigSHA256 = evidencecas.Digest([]byte("other-binding"))
			return &p
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := r.PersistentApprovalReference(forged); err == nil || got != (PersistentApprovalReference{}) {
				t.Fatalf("forged permit accepted: ref=%+v err=%v", got, err)
			}
		})
	}
	if got, err := r.PersistentApprovalReference(nil); err == nil || got != (PersistentApprovalReference{}) {
		t.Fatalf("nil permit accepted: ref=%+v err=%v", got, err)
	}
	other, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.PersistentApprovalReference(permit); err == nil {
		t.Fatal("foreign runtime accepted permit")
	}
	otherResolution, err := other.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	wrongResolution := *permit
	wrongResolution.resolution = otherResolution
	if _, err = r.PersistentApprovalReference(&wrongResolution); err == nil {
		t.Fatal("foreign resolution accepted")
	}
}

func TestRuntimePersistentApprovalReferenceRejectsHumanAndDevelopment(t *testing.T) {
	f := newRuntimeFixture(t)
	permitPolicy(t, f, "oss", "oss", "", "", nil, true)
	o := runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f})
	o.Transport, o.Human = "direct-interactive-cli", &acceptHuman{}
	r, err := NewRuntime(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	human, err := r.ReviewHuman(context.Background(), resolution, op, req)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := r.AuthorizeHuman(context.Background(), resolution, op, req, human)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.PersistentApprovalReference(permit); err == nil {
		t.Fatal("human permit exposed persistent approval reference")
	}
	if _, ok := any(&DevelopmentExecutionPermit{}).(*ExecutionPermit); ok {
		t.Fatal("development permit converted to stable permit")
	}
	if _, found := reflect.TypeOf((*DevelopmentRuntime)(nil)).MethodByName("PersistentApprovalReference"); found {
		t.Fatal("development runtime exposes stable approval projection")
	}
}

func TestRuntimeVerifiedSnapshotIsBoundAndDefensive(t *testing.T) {
	f := newRuntimeFixture(t)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingEvidenceReader{reader: runtimeStore(f.store)}
	r.options.Evidence = counted
	extBefore, polBefore, bundleBefore, projectBefore := ext.calls, pol.calls, bundle.calls, project.calls
	snapshot, err := r.VerifiedSnapshot(resolution)
	if err != nil || snapshot != resolution.snapshot || snapshot.Subject() != f.subject {
		t.Fatalf("VerifiedSnapshot snapshot=%p retained=%p subject=%+v err=%v", snapshot, resolution.snapshot, snapshot.Subject(), err)
	}
	if counted.reads != 0 || ext.calls != extBefore || pol.calls != polBefore || bundle.calls != bundleBefore || project.calls != projectBefore {
		t.Fatalf("snapshot projection performed I/O: evidence=%d ext=%d policy=%d bundle=%d project=%d", counted.reads, ext.calls-extBefore, pol.calls-polBefore, bundle.calls-bundleBefore, project.calls-projectBefore)
	}
	entries := snapshot.Entries()
	if len(entries) == 0 {
		t.Fatal("verified snapshot has no entries")
	}
	originalPath := entries[0].Path
	entries[0].Path = "mutated"
	if snapshot.Entries()[0].Path != originalPath {
		t.Fatal("entries accessor leaked retained slice")
	}
	contract := snapshot.ContractBytes()
	if len(contract) == 0 {
		t.Fatal("verified snapshot has no contract bytes")
	}
	originalContractByte := contract[0]
	contract[0] ^= 0xff
	if snapshot.ContractBytes()[0] != originalContractByte {
		t.Fatal("contract accessor leaked retained bytes")
	}
	sawBlob := false
	for _, entry := range snapshot.Entries() {
		blob, ok := snapshot.Blob(entry.Path)
		if !ok || len(blob) == 0 {
			continue
		}
		sawBlob = true
		original := blob[0]
		blob[0] ^= 0xff
		if again, ok := snapshot.Blob(entry.Path); !ok || again[0] != original {
			t.Fatal("blob accessor leaked retained bytes")
		}
		break
	}
	if !sawBlob {
		t.Fatal("verified snapshot has no readable blob")
	}
	if _, err = r.VerifiedSnapshot(nil); err == nil {
		t.Fatal("nil resolution accepted")
	}
	if _, err = r.VerifiedSnapshot(&VerifiedResolution{}); err == nil {
		t.Fatal("zero resolution accepted")
	}
	wrongBinding := *resolution
	wrongBinding.binding.ConfigSHA256 = evidencecas.Digest([]byte("other-binding"))
	if _, err = r.VerifiedSnapshot(&wrongBinding); err == nil {
		t.Fatal("same-runtime binding-mismatched resolution accepted")
	}
	other, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.VerifiedSnapshot(resolution); err == nil {
		t.Fatal("foreign runtime accepted snapshot projection")
	}
	if _, ok := any(&DevelopmentResolution{}).(*VerifiedResolution); ok {
		t.Fatal("development resolution converted to stable resolution")
	}
}

func TestHumanApprovalIsDirectCLIAndInvocationLocal(t *testing.T) {
	f := newRuntimeFixture(t)
	permitPolicy(t, f, "oss", "oss", "", "", nil, true)
	if _, err := DecodeExecutionPolicy(f.policy.PolicyJSON); err != nil {
		t.Fatalf("human policy decode: %v", err)
	}
	h := &acceptHuman{}
	o := runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f})
	o.Transport = "direct-interactive-cli"
	o.Human = h
	r, err := NewRuntime(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	human, err := r.ReviewHuman(context.Background(), res, op, req)
	if err != nil || h.calls != 1 {
		t.Fatalf("ReviewHuman=%v calls=%d", err, h.calls)
	}
	permit, err := r.AuthorizeHuman(context.Background(), res, op, req, human)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err != nil {
		t.Fatal(err)
	}
	o.Transport = "mcp"
	o.Human = h
	if _, err := NewRuntime(context.Background(), o); err == nil {
		t.Fatal("MCP runtime accepted human reviewer")
	}
	if _, err := r.Authorize(context.Background(), res, op, req, ApprovalRefs{Kind: "human", ApprovalCAS: evidencecas.Digest([]byte("human"))}); err == nil {
		t.Fatal("human reference entered persistent approval path")
	}
}

func organizationPermitRuntime(t *testing.T, f *runtimeFixture) *Runtime {
	t.Helper()
	var d bootstrap.DescriptorDocument
	if err := json.Unmarshal(f.ext.DescriptorJSON, &d); err != nil {
		t.Fatal(err)
	}
	d.Profile = bootstrap.ProfileOrganization
	d.DescriptorSHA256 = d.ComputedSHA256()
	dRaw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var p bootstrap.ProvisioningRecord
	if err = json.Unmarshal(f.ext.ProvisioningJSON, &p); err != nil {
		t.Fatal(err)
	}
	p.DescriptorSHA256 = d.DescriptorSHA256
	p.ProvisioningSHA256 = p.ComputedSHA256()
	pRaw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f.ext = bootstrap.ProvisionedSnapshot{DescriptorJSON: dRaw, ProvisioningJSON: pRaw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256}
	protected := protectedFixture{snapshot: bootstrap.ProtectedSnapshot{Envelope: f.bundle.Envelope, Receipt: f.bundle.Receipt, Transparency: f.bundle.Transparency, BackendID: "synthetic-protected", EvidenceClass: bootstrap.EvidenceProduction}}
	r, err := NewRuntime(context.Background(), StableOptions{Profile: bootstrap.ProfileOrganization, Project: &runtimeProject{f: f}, Policy: &runtimePolicy{f: f}, External: &runtimeExternal{f: f}, Protected: protected, Evidence: runtimeStore(f.store), Objects: f.objects, Clock: runtimeClock{fixture: f}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOrganizationApprovalRequiresIndependentPrincipalAndKey(t *testing.T) {
	cases := []struct {
		name, principal string
		key             func() ed25519.PrivateKey
		want            bool
	}{
		{"publisher-alias", "principal:publisher", func() ed25519.PrivateKey { return runtimeKey("org-alias") }, false},
		{"submitter", "principal:submitter", func() ed25519.PrivateKey { return runtimeKey("org-submitter") }, false},
		{"publisher-key-different-principal", "principal:approver", func() ed25519.PrivateKey { return runtimeKey("runtime-publisher") }, false},
		{"independent-principal", "principal:approver", func() ed25519.PrivateKey { return runtimeKey("org-independent") }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRuntimeFixture(t)
			f.project.MinimumProfile = "organization"
			key := tc.key()
			permitPolicy(t, f, "organization", "organization", tc.principal, "approver.test", key, false)
			r := organizationPermitRuntime(t, f)
			res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
			if err != nil {
				t.Fatal(err)
			}
			op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
			var p ExecutionPolicy
			if err = json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
				t.Fatal(err)
			}
			_, err = r.Authorize(context.Background(), res, op, req, persistentRefs(t, f, &p, req, key))
			if (err == nil) != tc.want {
				t.Fatalf("Authorize err=%v want success=%v", err, tc.want)
			}
		})
	}
}

func TestOrganizationTwoIssuerAliasesSamePrincipalRejectCandidateApproval(t *testing.T) {
	f := newRuntimeFixture(t)
	f.project.MinimumProfile = "organization"
	key := runtimeKey("alias-approver")
	permitPolicy(t, f, "organization", "organization", "principal:publisher", "approver-alias", key, false)
	var p ExecutionPolicy
	if err := json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	p.IssuerPrincipals = append(p.IssuerPrincipals, IssuerPrincipal{Issuer: "publisher-alias", PrincipalID: "principal:publisher"})
	aliasRule := p.SourceRules[0]
	aliasRule.Issuer = "publisher-alias"
	aliasRule.Origin = "https://example.test/alias-source"
	aliasRule.TemplatePath = "alias"
	aliasRule.Predicate = "https://example.test/alias-predicate"
	p.SourceRules = append(p.SourceRules, aliasRule)
	var err error
	p.PolicySHA256, err = p.ComputePolicySHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.policy.PolicyJSON, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.ExpectedPolicySHA256 = p.PolicySHA256
	r := organizationPermitRuntime(t, f)
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	// ApprovalRefs contains only the CAS locator and kind: neither it nor the
	// signed grant has a policy-principal mapping field to override the pinned
	// two-alias mapping. The matched publisher alias remains principal:publisher.
	if _, err = r.Authorize(context.Background(), res, op, req, persistentRefs(t, f, &p, req, key)); err == nil {
		t.Fatal("same-principal alias approval accepted")
	}
}

func developmentPermitRuntime(t *testing.T, f *runtimeFixture) *DevelopmentRuntime {
	t.Helper()
	var e bootstrap.Envelope
	if err := json.Unmarshal(f.bundle.Envelope, &e); err != nil {
		t.Fatal(err)
	}
	e.Signatures = []bootstrap.Signature{}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	leaf := bootstrap.HashLeaf([]byte(e.PayloadSHA256))
	cpRaw, err := json.Marshal(bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: e.AuthorityID, TreeSize: 1, RootHash: runtimeHash(leaf)})
	if err != nil {
		t.Fatal(err)
	}
	cp := runtimePut(f.store, cpRaw)
	proofRaw, err := json.Marshal(bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 1, Hashes: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	proof := runtimePut(f.store, proofRaw)
	r, err := NewDevelopmentRuntime(context.Background(), DevelopmentOptions{Objects: f.objects, Evidence: runtimeStore(f.store), Clock: runtimeClock{fixture: f}, Inputs: bootstrap.DevelopmentInputs{Envelope: raw, Transparency: bootstrap.TransparencyEvidence{CheckpointCAS: cp, InclusionProofCAS: proof}}, Project: &runtimeProject{f: f}, Policy: &runtimePolicy{f: f}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDevelopmentExecutionPermitIsSeparateAndRechecked(t *testing.T) {
	f := newRuntimeFixture(t)
	f.project.MinimumProfile = "development"
	key := runtimeKey("development-approver")
	permitPolicy(t, f, "development", "development", "principal:approver", "approver.test", key, false)
	r := developmentPermitRuntime(t, f)
	res, err := r.VerifySubject(context.Background(), f.subject)
	if err != nil {
		t.Fatal(err)
	}
	op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	var p ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	refs := persistentRefs(t, f, &p, req, key)
	permit, err := r.Authorize(context.Background(), res, op, req, refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(permit).(*ExecutionPermit); ok {
		t.Fatal("development permit converted to stable permit")
	}
	if err = r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err != nil {
		t.Fatal(err)
	}
	var zero DevelopmentExecutionPermit
	if err = r.RecheckExecution(context.Background(), &zero, req, stagedFixture{stage}); err == nil {
		t.Fatal("zero development permit accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Authorize(ctx, res, op, req, refs); !errors.Is(err, context.Canceled) {
		t.Fatalf("development Authorize cancellation=%v", err)
	}
	r.options.Evidence = &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: func() {
		var q ExecutionPolicy
		if e := json.Unmarshal(f.policy.PolicyJSON, &q); e != nil {
			t.Fatal(e)
		}
		q.PolicyID = "development-changed"
		var e error
		q.PolicySHA256, e = q.ComputePolicySHA256()
		if e != nil {
			t.Fatal(e)
		}
		f.policy.PolicyJSON, e = json.Marshal(q)
		if e != nil {
			t.Fatal(e)
		}
		f.policy.ExpectedPolicySHA256 = q.PolicySHA256
	}}
	if _, err = r.Authorize(context.Background(), res, op, req, refs); err == nil {
		t.Fatal("development changed policy during grant accepted")
	}
}

func TestDevelopmentHumanBindsRuntimeAndPolicyTimeout(t *testing.T) {
	f := newRuntimeFixture(t)
	f.project.MinimumProfile = "development"
	permitPolicy(t, f, "development", "development", "", "", nil, true)
	r := developmentPermitRuntime(t, f)
	r.options.Transport = "direct-interactive-cli"
	r.options.Human = &acceptHuman{}
	res, err := r.VerifySubject(context.Background(), f.subject)
	if err != nil {
		t.Fatal(err)
	}
	op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	human, err := r.ReviewHuman(context.Background(), res, op, req)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := r.AuthorizeHuman(context.Background(), res, op, req, human)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err != nil {
		t.Fatal(err)
	}
	foreignOp, foreignReq := cloneOperation(op), cloneRequest(req)
	foreign := "sha256:" + strings.Repeat("f", 64)
	foreignOp.ProfileBindingSHA256 = foreign
	foreignReq.ProfileBindingSHA256 = foreign
	var e error
	foreignReq.OperationInputsSHA256, e = ComputeOperationInputsSHA256(foreignOp)
	if e != nil {
		t.Fatal(e)
	}
	foreignReq.RequestSHA256, e = foreignReq.ComputeRequestSHA256()
	if e != nil {
		t.Fatal(e)
	}
	if _, err = r.ReviewHuman(context.Background(), res, foreignOp, foreignReq); err == nil {
		t.Fatal("foreign development binding human review accepted")
	}
	timeoutOp, timeoutReq := cloneOperation(op), cloneRequest(req)
	timeoutReq.TimeoutMillis = 1001
	timeoutOp.Actions[0].TimeoutMillis = 1001
	timeoutReq.OperationInputsSHA256, e = ComputeOperationInputsSHA256(timeoutOp)
	if e != nil {
		t.Fatal(e)
	}
	timeoutReq.RequestSHA256, e = timeoutReq.ComputeRequestSHA256()
	if e != nil {
		t.Fatal(e)
	}
	if _, err = r.ReviewHuman(context.Background(), res, timeoutOp, timeoutReq); err == nil {
		t.Fatal("development human timeout above policy accepted")
	}
	if _, err = r.AuthorizeHuman(context.Background(), res, foreignOp, foreignReq, human); err == nil {
		t.Fatal("foreign development binding human permit accepted")
	}
	if err = r.RecheckExecution(context.Background(), permit, foreignReq, stagedFixture{stage}); err == nil {
		t.Fatal("foreign development binding recheck accepted")
	}
	if _, err = r.AuthorizeHuman(context.Background(), res, timeoutOp, timeoutReq, human); err == nil {
		t.Fatal("development human timeout permit accepted")
	}
	if err = r.RecheckExecution(context.Background(), permit, timeoutReq, stagedFixture{stage}); err == nil {
		t.Fatal("development timeout recheck accepted")
	}
}

func copyStaged(m StagedMaterial) StagedMaterial {
	m.Operation = cloneOperation(m.Operation)
	m.Request = cloneRequest(m.Request)
	m.Content = append([]ContentEntry(nil), m.Content...)
	m.ContentBytes = make([][]byte, len(m.ContentBytes))
	for i := range m.ContentBytes {
		m.ContentBytes[i] = append([]byte(nil), m.ContentBytes[i]...)
	}
	m.ToolBytes = append([]byte(nil), m.ToolBytes...)
	m.ToolOptions = append([]string(nil), m.ToolOptions...)
	m.Environment.Variables = append([]EnvironmentVariable(nil), m.Environment.Variables...)
	return m
}

func rebuildStaged(t *testing.T, m *StagedMaterial) {
	t.Helper()
	var err error
	m.Request.Action.ContentClosureSHA256, err = ComputeContentClosureSHA256(m.Content)
	if err != nil {
		t.Fatal(err)
	}
	m.Request.Tool.BinarySHA256 = evidencecas.Digest(m.ToolBytes)
	m.Request.Tool.OptionsSHA256, err = ComputeToolOptionsSHA256(m.ToolOptions)
	if err != nil {
		t.Fatal(err)
	}
	m.Request.EnvironmentPolicySHA256, err = ComputeEnvironmentPolicySHA256(m.Environment)
	if err != nil {
		t.Fatal(err)
	}
	m.Operation.Actions[0] = ActionMaterial{Provider: m.Request.Provider, Action: cloneRequest(m.Request).Action, Tool: m.Request.Tool, WorkingDirectoryScope: m.Request.WorkingDirectoryScope, EnvironmentPolicySHA256: m.Request.EnvironmentPolicySHA256, TimeoutMillis: m.Request.TimeoutMillis, Migration: m.Request.Migration}
	m.Request.OperationInputsSHA256, err = ComputeOperationInputsSHA256(m.Operation)
	if err != nil {
		t.Fatal(err)
	}
	m.Request.RequestSHA256, err = m.Request.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecheckExecutionRejectsCompleteCandidateMutationMatrix(t *testing.T) {
	f := newRuntimeFixture(t)
	key := runtimeKey("matrix-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", key, false)
	r, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, base := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	var p ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	permit, err := r.Authorize(context.Background(), res, op, req, persistentRefs(t, f, &p, req, key))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*StagedMaterial)
	}{
		{"argv-0", func(m *StagedMaterial) { m.Request.Action.Argv[0] = "other-tool"; m.Request.Tool.ID = "other-tool" }},
		{"argv-1", func(m *StagedMaterial) { m.Request.Action.Argv[1] = "--changed" }},
		{"tool-version", func(m *StagedMaterial) { m.Request.Tool.Version = "2" }},
		{"tool-options", func(m *StagedMaterial) { m.ToolOptions = []string{"--changed"} }},
		{"closure-path", func(m *StagedMaterial) { m.Content[0].Path = "other.sh" }},
		{"closure-mode", func(m *StagedMaterial) { m.Content[0].Mode = "100644" }},
		{"cwd", func(m *StagedMaterial) { m.Request.WorkingDirectoryScope.Path = "nested" }},
		{"environment", func(m *StagedMaterial) { m.Environment.Variables[0].Value = "changed" }},
		{"timeout", func(m *StagedMaterial) { m.Request.TimeoutMillis = 101 }},
		{"migration-from", func(m *StagedMaterial) {
			m.Request.Migration = Migration{Kind: "version-transition", From: "v1", To: "v2"}
			m.Request.Action.Kind = "migration"
			m.Request.Scope = "migration"
			m.Operation.Scope = "migration"
		}},
		{"migration-to", func(m *StagedMaterial) {
			m.Request.Migration = Migration{Kind: "version-transition", From: "v1", To: "v3"}
			m.Request.Action.Kind = "migration"
			m.Request.Scope = "migration"
			m.Operation.Scope = "migration"
		}},
		{"closure-bytes", func(m *StagedMaterial) { m.ContentBytes[0] = []byte("other-staged-content") }},
		{"preimage", func(m *StagedMaterial) { m.Operation.PreimageSHA256 = evidencecas.Digest([]byte("changed-preimage")) }},
		{"answers", func(m *StagedMaterial) { m.Operation.AnswersSHA256 = evidencecas.Digest([]byte("changed-answers")) }},
		{"operation-subject", func(m *StagedMaterial) {
			m.Operation.Subjects[0].TreeSHA256 = evidencecas.Digest([]byte("changed-tree"))
		}},
		{"operation-action", func(m *StagedMaterial) { m.Operation.Actions[0].Action.Phase = "after" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := copyStaged(base)
			tc.mutate(&m)
			rebuildStaged(t, &m)
			if err := r.RecheckExecution(context.Background(), permit, req, stagedFixture{m}); err == nil {
				t.Fatal("changed complete candidate accepted")
			}
		})
	}
}

func TestPublicPermitCapabilitiesExpiryCancellationAndFreshGrantReads(t *testing.T) {
	f := newRuntimeFixture(t)
	key := runtimeKey("fresh-grant-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", key, false)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	var p ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	refs := persistentRefs(t, f, &p, req, key)
	// The policy mutation occurs while the verifier reads the grant. It is a
	// coherent replacement and must be caught by the final fresh resolution.
	o := runtimeOptions(f, ext, pol, bundle, project)
	s := &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: func() {
		var q ExecutionPolicy
		if e := json.Unmarshal(f.policy.PolicyJSON, &q); e != nil {
			t.Fatal(e)
		}
		q.PolicyID = "changed-during-grant"
		var e error
		q.PolicySHA256, e = q.ComputePolicySHA256()
		if e != nil {
			t.Fatal(e)
		}
		f.policy.PolicyJSON, e = json.Marshal(q)
		if e != nil {
			t.Fatal(e)
		}
		f.policy.ExpectedPolicySHA256 = q.PolicySHA256
	}}
	o.Evidence = s
	r, err = NewRuntime(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Authorize(context.Background(), res, op, req, refs); err == nil {
		t.Fatal("policy changed during grant accepted")
	}
	// Rebuild a valid fixture for cancellation and capability checks.
	f = newRuntimeFixture(t)
	key = runtimeKey("fresh-grant-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", key, false)
	r, err = NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	res, err = r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	if err = json.Unmarshal(f.policy.PolicyJSON, &p); err != nil {
		t.Fatal(err)
	}
	refs = persistentRefs(t, f, &p, req, key)
	ctx, cancel := context.WithCancel(context.Background())
	cs := &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: cancel}
	r.options.Evidence = cs
	if _, err = r.Authorize(ctx, res, op, req, refs); !errors.Is(err, context.Canceled) {
		t.Fatalf("Authorize cancellation=%v", err)
	}
	r.options.Evidence = runtimeStore(f.store)
	permit, err := r.Authorize(context.Background(), res, op, req, refs)
	if err != nil {
		t.Fatal(err)
	}
	var zero ExecutionPermit
	if err = r.RecheckExecution(context.Background(), &zero, req, stagedFixture{stage}); err == nil {
		t.Fatal("zero permit accepted")
	}
	other, err := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
	if err != nil {
		t.Fatal(err)
	}
	if err = other.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err == nil {
		t.Fatal("cross-runtime permit accepted")
	}
	// A project change while Recheck reads the grant must be caught by the
	// second complete authority/project/policy/source load.
	ms := &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: func() { f.project.ProjectID = "changed-project" }}
	r.options.Evidence = ms
	if err = r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); err == nil {
		t.Fatal("project changed during recheck grant accepted")
	}
	f.project.ProjectID = req.ProjectID
	ctx2, cancel2 := context.WithCancel(context.Background())
	r.options.Evidence = &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: cancel2}
	if err = r.RecheckExecution(ctx2, permit, req, stagedFixture{stage}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recheck cancellation=%v", err)
	}
}

func TestHumanExpiryAndDevelopmentNilAuthorizeAreSafe(t *testing.T) {
	var nilRuntime *DevelopmentRuntime
	if p, err := nilRuntime.Authorize(context.Background(), nil, OperationInputs{}, ExecutionRequest{}, ApprovalRefs{}); p != nil || err == nil {
		t.Fatalf("nil development authorize permit=%v err=%v", p, err)
	}
	f := newRuntimeFixture(t)
	permitPolicy(t, f, "oss", "oss", "", "", nil, true)
	h := &acceptHuman{}
	o := runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f})
	o.Transport = "direct-interactive-cli"
	o.Human = h
	r, err := NewRuntime(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	human, err := r.ReviewHuman(context.Background(), res, op, req)
	if err != nil {
		t.Fatal(err)
	}
	otherOpts := runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f})
	otherOpts.Transport = "direct-interactive-cli"
	otherOpts.Human = &acceptHuman{}
	other, err := NewRuntime(context.Background(), otherOpts)
	if err != nil {
		t.Fatal(err)
	}
	otherRes, err := other.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.AuthorizeHuman(context.Background(), otherRes, op, req, human); err == nil {
		t.Fatal("cross-runtime human capability accepted")
	}
	f.now = f.now.Add(301 * time.Second)
	if _, err = r.AuthorizeHuman(context.Background(), res, op, req, human); err == nil {
		t.Fatal("expired human approval accepted")
	}
	var reconstructed HumanApproval
	if err := json.Unmarshal([]byte(`{}`), &reconstructed); err != nil { //nolint:staticcheck // proves the opaque type cannot be reconstructed from JSON
		t.Fatal(err)
	}
	if _, err = r.AuthorizeHuman(context.Background(), res, op, req, &reconstructed); err == nil {
		t.Fatal("serialized human reconstruction accepted")
	}
	var zeroHuman *HumanApproval
	if _, err = r.AuthorizeHuman(context.Background(), res, op, req, zeroHuman); err == nil {
		t.Fatal("nil human capability accepted")
	}
	f2 := newRuntimeFixture(t)
	permitPolicy(t, f2, "oss", "oss", "", "", nil, true)
	ctx, cancel := context.WithCancel(context.Background())
	o2 := runtimeOptions(f2, &runtimeExternal{f: f2}, &runtimePolicy{f: f2}, &runtimeBundle{f: f2}, &runtimeProject{f: f2})
	o2.Transport = "direct-interactive-cli"
	o2.Human = cancelHuman{cancel}
	r2, e := NewRuntime(context.Background(), o2)
	if e != nil {
		t.Fatal(e)
	}
	res2, e := r2.VerifySubject(context.Background(), f2.subject, f2.refs)
	if e != nil {
		t.Fatal(e)
	}
	op2, req2, _ := permitInputs(t, r2.Binding(), f2.subject, f2.project.ProjectID)
	if _, e = r2.ReviewHuman(ctx, res2, op2, req2); !errors.Is(e, context.Canceled) {
		t.Fatalf("ReviewHuman cancellation=%v", e)
	}
}

func TestAuthorizeFreshReloadRejectsAuthorityPrincipalAndGrantChanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *runtimeFixture, ApprovalRefs)
	}{
		{"external", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) { mutateDescriptorRepin(t, f) }},
		{"bundle", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) { mutateReceiptCheckpointState(t, f) }},
		{"principal-mapping", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) {
			var p ExecutionPolicy
			if e := json.Unmarshal(f.policy.PolicyJSON, &p); e != nil {
				t.Fatal(e)
			}
			p.IssuerPrincipals[0].PrincipalID = "principal:submitter"
			var e error
			p.PolicySHA256, e = p.ComputePolicySHA256()
			if e != nil {
				t.Fatal(e)
			}
			f.policy.PolicyJSON, e = json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			f.policy.ExpectedPolicySHA256 = p.PolicySHA256
		}},
		{"grant-bytes", func(_ *testing.T, f *runtimeFixture, refs ApprovalRefs) {
			f.store[refs.ApprovalCAS] = []byte("altered-grant")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRuntimeFixture(t)
			key := runtimeKey("fresh-components")
			permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", key, false)
			ext, pol, bun, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
			r, e := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bun, project))
			if e != nil {
				t.Fatal(e)
			}
			res, e := r.VerifySubject(context.Background(), f.subject, f.refs)
			if e != nil {
				t.Fatal(e)
			}
			op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
			var p ExecutionPolicy
			if e = json.Unmarshal(f.policy.PolicyJSON, &p); e != nil {
				t.Fatal(e)
			}
			refs := persistentRefs(t, f, &p, req, key)
			r.options.Evidence = &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: func() { tc.mutate(t, f, refs) }}
			if _, e = r.Authorize(context.Background(), res, op, req, refs); e == nil {
				t.Fatal("changed component accepted")
			}
		})
	}
}

func TestRecheckFreshReloadRejectsAuthorityPrincipalAndGrantChanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *runtimeFixture, ApprovalRefs)
	}{
		{"external", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) { mutateDescriptorRepin(t, f) }},
		{"bundle", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) { mutateReceiptCheckpointState(t, f) }},
		{"principal-mapping", func(t *testing.T, f *runtimeFixture, _ ApprovalRefs) {
			var p ExecutionPolicy
			if e := json.Unmarshal(f.policy.PolicyJSON, &p); e != nil {
				t.Fatal(e)
			}
			p.IssuerPrincipals[0].PrincipalID = "principal:submitter"
			var e error
			p.PolicySHA256, e = p.ComputePolicySHA256()
			if e != nil {
				t.Fatal(e)
			}
			f.policy.PolicyJSON, e = json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			f.policy.ExpectedPolicySHA256 = p.PolicySHA256
		}},
		{"grant-bytes", func(_ *testing.T, f *runtimeFixture, refs ApprovalRefs) {
			f.store[refs.ApprovalCAS] = []byte("altered-grant")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRuntimeFixture(t)
			key := runtimeKey("recheck-components")
			permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", key, false)
			r, e := NewRuntime(context.Background(), runtimeOptions(f, &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}))
			if e != nil {
				t.Fatal(e)
			}
			res, e := r.VerifySubject(context.Background(), f.subject, f.refs)
			if e != nil {
				t.Fatal(e)
			}
			op, req, stage := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
			var p ExecutionPolicy
			if e = json.Unmarshal(f.policy.PolicyJSON, &p); e != nil {
				t.Fatal(e)
			}
			refs := persistentRefs(t, f, &p, req, key)
			permit, e := r.Authorize(context.Background(), res, op, req, refs)
			if e != nil {
				t.Fatal(e)
			}
			r.options.Evidence = &mutationStore{runtimeStore: runtimeStore(f.store), target: refs.ApprovalCAS, armed: true, mutate: func() { tc.mutate(t, f, refs) }}
			if e = r.RecheckExecution(context.Background(), permit, req, stagedFixture{stage}); e == nil {
				t.Fatal("recheck accepted changed component")
			}
		})
	}
}

// Publication checks reuse the actual current signed-grant boundary without
// minting a process permit. Fixture signatures represent local test authority.
func TestRuntimePublicationApprovalUsesCurrentExactGrant(t *testing.T) {
	f := newRuntimeFixture(t)
	approver := runtimeKey("publication-current-approver")
	permitPolicy(t, f, "oss", "oss", "principal:approver", "approver.test", approver, false)
	ext, pol, bundle, project := &runtimeExternal{f: f}, &runtimePolicy{f: f}, &runtimeBundle{f: f}, &runtimeProject{f: f}
	r, err := NewRuntime(context.Background(), runtimeOptions(f, ext, pol, bundle, project))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := r.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	op, req, _ := permitInputs(t, r.Binding(), f.subject, f.project.ProjectID)
	var policy ExecutionPolicy
	if err = json.Unmarshal(f.policy.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	refs := persistentRefs(t, f, &policy, req, approver)
	approval, err := DecodeExecutionApproval(f.store[refs.ApprovalCAS])
	if err != nil {
		t.Fatal(err)
	}
	ref := PersistentApprovalReference{RequestSHA256: req.RequestSHA256, GrantSHA256: approval.GrantSHA256, ApprovalCAS: refs.ApprovalCAS}
	before := ext.calls
	if err = r.VerifyPublicationApproval(context.Background(), resolution, op, req, ref); err != nil {
		t.Fatal(err)
	}
	if ext.calls <= before {
		t.Fatal("publication did not recheck current external authority")
	}
	for name, bad := range map[string]PersistentApprovalReference{
		"request": {RequestSHA256: evidencecas.Digest([]byte("other request")), GrantSHA256: ref.GrantSHA256, ApprovalCAS: ref.ApprovalCAS},
		"grant":   {RequestSHA256: ref.RequestSHA256, GrantSHA256: evidencecas.Digest([]byte("other grant")), ApprovalCAS: ref.ApprovalCAS},
		"missing": {RequestSHA256: ref.RequestSHA256, GrantSHA256: ref.GrantSHA256, ApprovalCAS: evidencecas.Digest([]byte("missing"))},
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.VerifyPublicationApproval(context.Background(), resolution, op, req, bad); err == nil {
				t.Fatal("mismatched publication grant accepted")
			}
		})
	}
	wrong := req
	wrong.Scope = "new"
	wrong.RequestSHA256, _ = wrong.ComputeRequestSHA256()
	if err := r.VerifyPublicationApproval(context.Background(), resolution, op, wrong, ref); err == nil {
		t.Fatal("different operation scope accepted")
	}
	if err := r.VerifyPublicationApproval(nil, resolution, op, req, ref); err == nil {
		t.Fatal("nil context accepted")
	}
	f.now = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := r.VerifyPublicationApproval(context.Background(), resolution, op, req, ref); err == nil {
		t.Fatal("expired approval accepted at publication")
	}
}
