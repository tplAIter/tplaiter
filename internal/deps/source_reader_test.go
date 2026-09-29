package deps

import (
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// readerFixture constructs a real stable Runtime through its public bootstrap
// inputs, then gets the resolution through VerifySubject. It never constructs
// an authority, snapshot, or resolution capability directly.
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

func readerRuntime(t *testing.T) (*trustverify.Runtime, *trustverify.VerifiedResolution, *readerFixture) {
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

func readerPin(t *testing.T, r *trustverify.Runtime, res *trustverify.VerifiedResolution, f *readerFixture) PinnedSource {
	t.Helper()
	snap, err := r.VerifiedSnapshot(res)
	if err != nil {
		t.Fatal(err)
	}
	content, err := SnapshotContentDigest(snap.Entries())
	if err != nil {
		t.Fatal(err)
	}
	return PinnedSource{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "source", ProviderID: "provider.fixture", Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath, RequestedRef: f.subject.RequestedRef, CommitAlgorithm: "sha1", Commit: f.subject.Commit, TreeDigest: f.subject.TreeSHA256, ContentDigest: content, ContractDigest: f.subject.ContractSHA256, EvidenceDigest: f.refs.StatementCAS, Parameters: []Parameter{}, Dependencies: []string{}}
}

func TestSourceReaderUsesActualRuntimeBoundSnapshot(t *testing.T) {
	r, res, f := readerRuntime(t)
	reader, err := NewSourceReader(r)
	if err != nil {
		t.Fatal(err)
	}
	pin := readerPin(t, r, res, f)
	got, err := reader.Read(context.Background(), res, pin)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject() != f.subject || len(got.Entries()) != 3 {
		t.Fatalf("subject/entries=%+v", got)
	}
	b, _ := got.Blob("run.sh")
	b[0] = 'X'
	again, _ := got.Blob("run.sh")
	if again[0] == 'X' {
		t.Fatal("reader returned mutable blob")
	}
	c := got.ContractBytes()
	c[0] = 'X'
	if got.ContractBytes()[0] == 'X' {
		t.Fatal("reader returned mutable contract")
	}
}

func TestSourceReaderRejectsMismatchedPinAndCancellation(t *testing.T) {
	r, res, f := readerRuntime(t)
	reader, _ := NewSourceReader(r)
	pin := readerPin(t, r, res, f)
	for _, tc := range []struct {
		mutate func(*PinnedSource)
		want   string
	}{
		{func(p *PinnedSource) { p.Commit = "0123456789012345678901234567890123456789" }, SourceInvalid},
		{func(p *PinnedSource) { p.TreeDigest = "sha256:" + strings.Repeat("0", 64) }, SourceInvalid},
		{func(p *PinnedSource) { p.ContentDigest = "sha256:" + strings.Repeat("0", 64) }, SourceContentMismatch},
		{func(p *PinnedSource) { p.ContractDigest = "sha256:" + strings.Repeat("0", 64) }, SourceInvalid},
		{func(p *PinnedSource) { p.EvidenceDigest = "sha256:" + strings.Repeat("0", 64) }, SourceEvidenceMismatch},
	} {
		p := pin
		tc.mutate(&p)
		if _, err := reader.Read(context.Background(), res, p); err == nil || !hasCode(err, tc.want) {
			t.Fatalf("mismatched immutable pin accepted or wrong type: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.Read(ctx, res, pin); err == nil {
		t.Fatal("cancelled read accepted")
	}
}

func TestSourceReaderRejectsUnboundResolutionAndNilRuntime(t *testing.T) {
	if _, err := NewSourceReader(nil); err == nil {
		t.Fatal("nil runtime accepted")
	}
	r, res, f := readerRuntime(t)
	reader, err := NewSourceReader(r)
	if err != nil {
		t.Fatal(err)
	}
	pin := readerPin(t, r, res, f)
	if _, err := reader.Read(context.Background(), nil, pin); err == nil || !hasCode(err, SourceSnapshotUnavailable) {
		t.Fatalf("nil resolution accepted or wrong type: %v", err)
	}
	foreign, _, _ := readerRuntime(t)
	foreignReader, err := NewSourceReader(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignReader.Read(context.Background(), res, pin); err == nil {
		t.Fatal("foreign runtime resolution accepted")
	}
}
