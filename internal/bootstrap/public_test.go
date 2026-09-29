package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func publisherFixture(t *testing.T) (*Verifier, *Authority, PublisherExpectation, PublisherEvidence, PublisherStatement) {
	t.Helper()
	v, ext, candidate, _ := externalFixture(t, ProfileOSS)
	a, err := v.VerifyOSS(context.Background(), ext, candidate)
	if err != nil {
		t.Fatal(err)
	}
	x := PublisherExpectation{PolicyOrigin: "https://example.test/policy", Issuer: "synthetic", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: SubjectIdentity{Origin: "https://example.test/source", TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: digest(), ContractSHA256: digest()}}
	s := PublisherStatement{APIVersion: PublisherStatementAPIVersion, PolicyOrigin: x.PolicyOrigin, Issuer: x.Issuer, Predicate: x.Predicate, Usage: x.Usage, Subject: x.Subject}
	statement, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DomainDigest(PublisherStatementAPIVersion, s)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	signature := []byte(EncodeSignature(ed25519.Sign(private, mustRaw(t, d))))
	store := v.store.(memoryEvidence)
	statementCAS, signatureCAS := evidencecas.Digest(statement), evidencecas.Digest(signature)
	store[statementCAS], store[signatureCAS] = statement, signature
	return v, a, x, PublisherEvidence{StatementCAS: statementCAS, SignatureCAS: signatureCAS, KeyFingerprint: Fingerprint(private.Public().(ed25519.PublicKey))}, s
}

func signedPublisherEvidence(t *testing.T, v *Verifier, x PublisherExpectation, private ed25519.PrivateKey) PublisherEvidence {
	t.Helper()
	s := PublisherStatement{APIVersion: PublisherStatementAPIVersion, PolicyOrigin: x.PolicyOrigin, Issuer: x.Issuer, Predicate: x.Predicate, Usage: x.Usage, Subject: x.Subject}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DomainDigest(PublisherStatementAPIVersion, s)
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(EncodeSignature(ed25519.Sign(private, mustRaw(t, d))))
	statementCAS, signatureCAS := evidencecas.Digest(raw), evidencecas.Digest(sig)
	store := v.store.(memoryEvidence)
	store[statementCAS], store[signatureCAS] = raw, sig
	return PublisherEvidence{StatementCAS: statementCAS, SignatureCAS: signatureCAS, KeyFingerprint: Fingerprint(private.Public().(ed25519.PublicKey))}
}

func twoTupleClaimFixture(t *testing.T) (*Verifier, *Authority, PublisherExpectation, PublisherExpectation, ed25519.PrivateKey) {
	t.Helper()
	v, ext, current, _ := externalFixture(t, ProfileOSS)
	currentEnvelope, err := DecodeEnvelope(current.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	store := v.store.(memoryEvidence)
	root := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	rootPub := root.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytes32("t2-other-root"))
	otherPub := other.Public().(ed25519.PublicKey)
	rootRef, otherRef := evidencecas.Digest([]byte(EncodePublicKey(rootPub))), evidencecas.Digest([]byte(EncodePublicKey(otherPub)))
	store[rootRef], store[otherRef] = []byte(EncodePublicKey(rootPub)), []byte(EncodePublicKey(otherPub))
	e := Envelope{APIVersion: TrustRootsAPIVersion, AuthorityID: currentEnvelope.AuthorityID, Sequence: 1, Validity: currentEnvelope.Validity, AllowedPolicyOrigins: []string{"https://example.test/policy", "https://example.test/policy-b"}, RootKeys: []RootKey{{Fingerprint: Fingerprint(rootPub), PublicKeyCAS: rootRef, Issuer: "synthetic", Status: "active"}, {Fingerprint: Fingerprint(otherPub), PublicKeyCAS: otherRef, Issuer: "other", Status: "active"}}, Threshold: 1, RevocationEpoch: 1, Revocations: []Revocation{}}
	sort.Slice(e.RootKeys, func(i, j int) bool { return e.RootKeys[i].Fingerprint < e.RootKeys[j].Fingerprint })
	e.PayloadSHA256, err = e.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	anchor := ed25519.NewKeyFromSeed(bytes32("t2-anchor"))
	anchorSignature := []byte(EncodeSignature(ed25519.Sign(anchor, mustRaw(t, e.PayloadSHA256))))
	anchorRef := evidencecas.Digest(anchorSignature)
	store[anchorRef] = anchorSignature
	e.Signatures = []Signature{{KeyFingerprint: Fingerprint(anchor.Public().(ed25519.PublicKey)), SignatureCAS: anchorRef}}
	leaf := HashLeaf([]byte(e.PayloadSHA256))
	checkpointRef := put(store, Checkpoint{APIVersion: CheckpointAPIVersion, AuthorityID: e.AuthorityID, TreeSize: 1, RootHash: hashText(leaf)})
	inclusionRef := put(store, InclusionProof{APIVersion: InclusionAPIVersion, LeafIndex: 0, TreeSize: 1, Hashes: []string{}})
	r := Receipt{APIVersion: TrustReceiptAPIVersion, AuthorityID: e.AuthorityID, HighestAcceptedSequence: e.Sequence, EnvelopePayloadSHA256: e.PayloadSHA256, RevocationEpoch: e.RevocationEpoch, TreeSize: 1, CheckpointDigest: checkpointRef}
	r.ReceiptDigest, err = r.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	rawEnvelope, _ := json.Marshal(e)
	rawReceipt, _ := json.Marshal(r)
	d := ext.descriptor
	d.AllowedPolicyOrigins = []string{"https://example.test/policy", "https://example.test/policy-b"}
	d.PublisherScopes = append([]PublisherScope(nil), d.PublisherScopes...)
	d.PublisherScopes = append(d.PublisherScopes, PublisherScope{PolicyOrigin: "https://example.test/policy-b", Issuer: "other", SourceOrigin: "https://example.test/source-b", TemplatePath: "templates/allowed", Predicate: "https://example.test/predicate-b", Usage: "template-source"})
	d.DescriptorSHA256 = d.ComputedSHA256()
	p := ext.provisioning
	p.DescriptorSHA256 = d.DescriptorSHA256
	p.ProvisioningSHA256 = p.ComputedSHA256()
	s := OSSAcceptedState{APIVersion: OSSAcceptedStateAPIVersion, DescriptorSHA256: d.DescriptorSHA256, ProvisioningSHA256: p.ProvisioningSHA256, AuthorityID: e.AuthorityID, Sequence: e.Sequence, EnvelopePayloadSHA256: e.PayloadSHA256, RevocationEpoch: e.RevocationEpoch, ReceiptDigest: r.ReceiptDigest, TreeSize: r.TreeSize, CheckpointDigest: r.CheckpointDigest}
	s.StateSHA256 = s.ComputedSHA256()
	snap := ProvisionedSnapshot{}
	snap.DescriptorJSON, _ = json.Marshal(d)
	snap.ProvisioningJSON, _ = json.Marshal(p)
	snap.OSSStateJSON, _ = json.Marshal(s)
	snap.ExpectedDescriptorSHA256, snap.ExpectedProvisioningSHA256, snap.ExpectedOSSStateSHA256, snap.InitialOSSStateSHA256 = d.DescriptorSHA256, p.ProvisioningSHA256, s.StateSHA256, s.StateSHA256
	loaded, err := LoadExternal(context.Background(), fixedExternalReader{snap})
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.VerifyOSS(context.Background(), loaded, Bundle{Envelope: rawEnvelope, Receipt: rawReceipt, Transparency: TransparencyEvidence{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef}})
	if err != nil {
		t.Fatal(err)
	}
	first := PublisherExpectation{PolicyOrigin: "https://example.test/policy", Issuer: "synthetic", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: SubjectIdentity{Origin: "https://example.test/source", TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: digest(), ContractSHA256: digest()}}
	second := PublisherExpectation{PolicyOrigin: "https://example.test/policy-b", Issuer: "other", Predicate: "https://example.test/predicate-b", Usage: "template-source", Subject: SubjectIdentity{Origin: "https://example.test/source-b", TemplatePath: "templates/allowed", Commit: strings.Repeat("b", 40), TreeSHA256: digest(), ContractSHA256: digest()}}
	return v, a, first, second, other
}

func requirePublisherScopeDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil || err.Error() != "bootstrap: publisher scope denied" {
		t.Fatalf("publisher tuple check = %v", err)
	}
}

func TestVerifyPublisherClaimTypedTupleAndGoldenFraming(t *testing.T) {
	v, a, x, refs, statement := publisherFixture(t)
	claim, err := v.VerifyPublisherClaim(context.Background(), a, x, refs)
	if err != nil {
		t.Fatal(err)
	}
	if claim.AuthoritySHA256() != a.Binding().AuthoritySHA256 || claim.Expectation() != x {
		t.Fatal("claim did not retain exact expectation and authority binding")
	}
	const canonical = `{"apiVersion":"tplaiter.dev/publisher-statement/v1","issuer":"synthetic","policyOrigin":"https://example.test/policy","predicate":"https://example.test/predicate","subject":{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","contractSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","origin":"https://example.test/source","templatePath":".","treeSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"usage":"template-source"}`
	sum := sha256.Sum256(append(append([]byte(PublisherStatementAPIVersion), 0), []byte(canonical)...))
	const golden = "sha256:436b70b6795f21ecdbb2c6646c98959304eb8b6261eb24f485044274ab3599c5"
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != golden {
		t.Fatalf("independent publisher statement framing digest = %s", got)
	}
	d, err := DomainDigest(PublisherStatementAPIVersion, statement)
	if err != nil {
		t.Fatal(err)
	}
	if d != golden {
		t.Fatalf("publisher statement domain digest = %s", d)
	}
	wrongDomain, err := DomainDigest("tplaiter.dev/publisher-statement/v0", statement)
	if err != nil {
		t.Fatal(err)
	}
	bad := refs
	wrongSignature := []byte(EncodeSignature(ed25519.Sign(ed25519.NewKeyFromSeed(bytes32("t2-root")), mustRaw(t, wrongDomain))))
	bad.SignatureCAS = evidencecas.Digest(wrongSignature)
	v.store.(memoryEvidence)[bad.SignatureCAS] = wrongSignature
	if _, err := v.VerifyPublisherClaim(context.Background(), a, x, bad); err == nil {
		t.Fatal("signature with another statement domain accepted")
	}
}

func TestVerifyPublisherClaimRequiresExactTuple(t *testing.T) {
	v, a, first, second, other := twoTupleClaimFixture(t)
	firstPrivate := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	if _, err := v.VerifyPublisherClaim(context.Background(), a, first, signedPublisherEvidence(t, v, first, firstPrivate)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyPublisherClaim(context.Background(), a, second, signedPublisherEvidence(t, v, second, other)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PublisherExpectation){
		func(x *PublisherExpectation) { x.PolicyOrigin = first.PolicyOrigin },
		func(x *PublisherExpectation) { x.Subject.Origin = first.Subject.Origin },
		func(x *PublisherExpectation) { x.Subject.TemplatePath = first.Subject.TemplatePath },
		func(x *PublisherExpectation) { x.Predicate = first.Predicate },
		func(x *PublisherExpectation) { x.Subject.TemplatePath = "templates" },
		func(x *PublisherExpectation) { x.Subject.TemplatePath = "templates/allowed/file" },
		func(x *PublisherExpectation) { x.Subject.TemplatePath = "templates/allowed2" },
		func(x *PublisherExpectation) { x.Subject.Origin = "ssh://example.test/source-b" },
		func(x *PublisherExpectation) { x.Subject.Origin = "https://example.test/source-b.git" },
		func(x *PublisherExpectation) { x.Subject.Origin = "https://example.test/source-b/" },
	} {
		mixed := second
		mutate(&mixed)
		refs := signedPublisherEvidence(t, v, mixed, other)
		_, err := v.VerifyPublisherClaim(context.Background(), a, mixed, refs)
		requirePublisherScopeDenied(t, err)
	}
}

func TestVerifyPublisherClaimRechecksExpiryRevocationAndIssuer(t *testing.T) {
	v, a, x, refs, _ := publisherFixture(t)
	expired := *a
	expired.envelope.Validity.NotAfter = "2026-01-01T00:00:00Z"
	if _, err := v.VerifyPublisherClaim(context.Background(), &expired, x, refs); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired authority claim = %v", err)
	}
	revokedAuthority := *a
	revokedAuthority.envelope.Revocations = []Revocation{{Fingerprint: refs.KeyFingerprint, EffectiveSequence: 1}}
	if _, err := v.VerifyPublisherClaim(context.Background(), &revokedAuthority, x, refs); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked authority claim = %v", err)
	}
	issuerScope := *a
	issuerScope.publisherScopes = append(append([]PublisherScope(nil), a.publisherScopes...), PublisherScope{PolicyOrigin: x.PolicyOrigin, Issuer: "other", SourceOrigin: x.Subject.Origin, TemplatePath: x.Subject.TemplatePath, Predicate: x.Predicate, Usage: x.Usage})
	wrongIssuer := x
	wrongIssuer.Issuer = "other"
	if _, err := v.VerifyPublisherClaim(context.Background(), &issuerScope, wrongIssuer, refs); err == nil {
		t.Fatal("active key with a different authenticated issuer accepted")
	}
}

func TestVerifyPublisherClaimEvidenceAndCancellation(t *testing.T) {
	v, a, x, refs, _ := publisherFixture(t)
	missing := *v
	missing.store = memoryEvidence{}
	if _, err := missing.VerifyPublisherClaim(context.Background(), a, x, refs); !errors.Is(err, ErrEvidenceMissing) {
		t.Fatalf("missing statement = %v", err)
	}
	tampered := *v
	tampered.store = memoryEvidence{refs.StatementCAS: []byte(`{}`)}
	if _, err := tampered.VerifyPublisherClaim(context.Background(), a, x, refs); !errors.Is(err, ErrEvidenceMismatch) {
		t.Fatalf("tampered statement = %v", err)
	}
	large := make([]byte, maxEvidenceSize+1)
	largeRef := evidencecas.Digest(large)
	oversized := *v
	oversized.store = memoryEvidence{largeRef: large}
	bad := refs
	bad.StatementCAS = largeRef
	if _, err := oversized.VerifyPublisherClaim(context.Background(), a, x, bad); !errors.Is(err, ErrEvidenceOversize) {
		t.Fatalf("oversized statement = %v", err)
	}
	for _, tc := range []struct {
		name  string
		store memoryEvidence
		refs  PublisherEvidence
		want  error
	}{
		{"missing signature", memoryEvidence{refs.StatementCAS: v.store.(memoryEvidence)[refs.StatementCAS]}, refs, ErrEvidenceMissing},
		{"tampered signature", memoryEvidence{refs.StatementCAS: v.store.(memoryEvidence)[refs.StatementCAS], refs.SignatureCAS: []byte("not-a-signature")}, refs, ErrEvidenceMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := *v
			reader.store = tc.store
			if _, err := reader.VerifyPublisherClaim(context.Background(), a, x, tc.refs); !errors.Is(err, tc.want) {
				t.Fatalf("signature CAS error = %v", err)
			}
		})
	}
	largeSignature := make([]byte, maxEvidenceSize+1)
	largeSignatureRef := evidencecas.Digest(largeSignature)
	signatureOversized := *v
	signatureOversized.store = memoryEvidence{refs.StatementCAS: v.store.(memoryEvidence)[refs.StatementCAS], largeSignatureRef: largeSignature}
	badSignature := refs
	badSignature.SignatureCAS = largeSignatureRef
	if _, err := signatureOversized.VerifyPublisherClaim(context.Background(), a, x, badSignature); !errors.Is(err, ErrEvidenceOversize) {
		t.Fatalf("oversized signature = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifyPublisherClaim(ctx, a, x, refs); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled claim = %v", err)
	}
	if _, err := v.VerifyPublisherClaim(nil, a, x, refs); err == nil { //nolint:staticcheck // deliberately exercises nil-context rejection
		t.Fatal("nil context accepted")
	}
}

func TestVerifyPublisherClaimRejectsPostSigningStatementMutation(t *testing.T) {
	v, a, x, refs, statement := publisherFixture(t)
	statement.Subject.Commit = strings.Repeat("b", 40)
	mutated, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	mutatedRef := evidencecas.Digest(mutated)
	v.store.(memoryEvidence)[mutatedRef] = mutated
	refs.StatementCAS = mutatedRef
	x.Subject.Commit = statement.Subject.Commit
	_, err = v.VerifyPublisherClaim(context.Background(), a, x, refs)
	if err == nil || err.Error() != "bootstrap: invalid publisher signature" {
		t.Fatalf("post-signing statement mutation = %v", err)
	}
}

func TestDecodePublisherStatementAndSchemaOracle(t *testing.T) {
	_, _, _, _, statement := publisherFixture(t)
	valid, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	rawSchema, err := os.ReadFile("../../schema/publisher-statement.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(rawSchema)))
	if err != nil {
		t.Fatal(err)
	}
	compiler := js.NewCompiler()
	if err := compiler.AddResource("https://schemas.invalid/publisher-statement.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://schemas.invalid/publisher-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	check := func(raw []byte) (bool, bool) {
		_, decodeErr := DecodePublisherStatement(raw)
		value, jsonErr := js.UnmarshalJSON(strings.NewReader(string(raw)))
		if jsonErr != nil {
			return decodeErr == nil, false
		}
		return decodeErr == nil, schema.Validate(value) == nil
	}
	if goOK, schemaOK := check(valid); !goOK || !schemaOK {
		t.Fatalf("valid statement parity go=%t schema=%t", goOK, schemaOK)
	}
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy","issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"},"unknown":true}`),
		[]byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy","issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `"}}`),
		[]byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy","issuer":null,"predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"}}`),
	} {
		goOK, schemaOK := check(raw)
		if goOK || schemaOK {
			t.Fatalf("invalid publisher statement parity go=%t schema=%t raw=%q", goOK, schemaOK, raw)
		}
	}
	duplicate := []byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy","issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"}}`)
	if _, err := DecodePublisherStatement(duplicate); err == nil {
		t.Fatal("strict decoder accepted duplicate field")
	}
	if value, err := js.UnmarshalJSON(strings.NewReader(string(duplicate))); err != nil || schema.Validate(value) != nil {
		t.Fatal("schema oracle should receive the duplicate-collapsed JSON value")
	}
	if _, err := DecodePublisherStatement(append([]byte(`{"apiVersion":"`), append([]byte{0xff}, []byte(`"}`)...)...)); err == nil {
		t.Fatal("strict decoder accepted invalid UTF-8")
	}
	for _, path := range []string{".", strings.Repeat("т", 1024)} {
		var changed PublisherStatement
		if err := json.Unmarshal(valid, &changed); err != nil {
			t.Fatal(err)
		}
		changed.Subject.TemplatePath = path
		raw, _ := json.Marshal(changed)
		goOK, schemaOK := check(raw)
		if !goOK || !schemaOK {
			t.Fatalf("safe path parity go=%t schema=%t path=%q", goOK, schemaOK, path)
		}
	}
	var tooLong PublisherStatement
	if err := json.Unmarshal(valid, &tooLong); err != nil {
		t.Fatal(err)
	}
	tooLong.Subject.TemplatePath = strings.Repeat("т", 1025)
	rawTooLong, _ := json.Marshal(tooLong)
	if goOK, schemaOK := check(rawTooLong); goOK || schemaOK {
		t.Fatalf("1025-code-point path parity go=%t schema=%t", goOK, schemaOK)
	}
	wrongType := []byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":7,"issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"}}`)
	if goOK, schemaOK := check(wrongType); goOK || schemaOK {
		t.Fatalf("wrong-type parity go=%t schema=%t", goOK, schemaOK)
	}
	queryOrigin := []byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy?query","issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":".","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"}}`)
	if goOK, schemaOK := check(queryOrigin); goOK || !schemaOK {
		t.Fatalf("runtime-only URI parser facet go=%t schema=%t", goOK, schemaOK)
	}
	dotPath := []byte(`{"apiVersion":"tplaiter.dev/publisher-statement/v1","policyOrigin":"https://example.test/policy","issuer":"synthetic","predicate":"https://example.test/predicate","usage":"template-source","subject":{"origin":"https://example.test/source","templatePath":"templates/./base","commit":"` + strings.Repeat("a", 40) + `","treeSHA256":"` + digest() + `","contractSHA256":"` + digest() + `"}}`)
	if goOK, schemaOK := check(dotPath); goOK || schemaOK {
		t.Fatalf("path facet parity go=%t schema=%t", goOK, schemaOK)
	}
}
