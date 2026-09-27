package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

func TestMerkleRejectsInvalidBounds(t *testing.T) {
	if VerifyInclusion([]byte("x"), 0, 0, MerkleHash{}, nil) == nil {
		t.Fatal("accepted empty tree")
	}
}

func TestEnvelopeWirePresenceAndRotation(t *testing.T) {
	fx := newWireEnvelope(t)
	raw, _ := json.Marshal(fx)
	if _, err := DecodeEnvelope(raw); err != nil {
		t.Fatalf("rotation envelope rejected: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "revocationEpoch")
	missing, _ := json.Marshal(doc)
	if _, err := DecodeEnvelope(missing); err == nil {
		t.Fatal("missing zero-valued revocation epoch accepted")
	}
	doc = map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	sigs := doc["signatures"].([]any)
	sigs[0].(map[string]any)["unknown"] = "x"
	bad, _ := json.Marshal(doc)
	if _, err := DecodeEnvelope(bad); err == nil {
		t.Fatal("unknown nested signature accepted")
	}
}

func newWireEnvelope(t *testing.T) Envelope {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	e := Envelope{APIVersion: TrustRootsAPIVersion, AuthorityID: "wire-test", Sequence: 2, Validity: Validity{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []RootKey{{Fingerprint(key), digest(), "issuer", "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []Revocation{}, Rotation: &Rotation{PreviousSequence: 1, OverlapUntil: "2026-06-01T00:00:00Z"}, Signatures: []Signature{{Fingerprint(key), digest()}}}
	var err error
	e.PayloadSHA256, err = e.ComputePayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type memoryEvidence map[string][]byte

func (m memoryEvidence) Read(_ context.Context, digest string) ([]byte, error) {
	return append([]byte(nil), m[digest]...), nil
}
func put(m memoryEvidence, value any) string {
	raw, _ := json.Marshal(value)
	d := evidencecas.Digest(raw)
	m[d] = raw
	return d
}

func TestVerifyOSSUsesExternalAnchor(t *testing.T) {
	seed := sha256.Sum256([]byte("anchor"))
	pub, private, _ := ed25519.GenerateKey(strings.NewReader(strings.Repeat(string(seed[:]), 8)))
	rootSeed := sha256.Sum256([]byte("publisher"))
	root, _, _ := ed25519.GenerateKey(strings.NewReader(strings.Repeat(string(rootSeed[:]), 8)))
	m := memoryEvidence{}
	rootRef := evidencecas.Digest([]byte(EncodePublicKey(root)))
	m[rootRef] = []byte(EncodePublicKey(root))
	e := Envelope{APIVersion: TrustRootsAPIVersion, AuthorityID: "synthetic", Sequence: 1, Validity: Validity{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []RootKey{{Fingerprint(root), rootRef, "synthetic", "active"}}, Threshold: 1, RevocationEpoch: 1, Revocations: []Revocation{}}
	e.PayloadSHA256, _ = e.ComputePayloadSHA256()
	sig := ed25519.Sign(private, mustRaw(t, e.PayloadSHA256))
	sigRef := evidencecas.Digest([]byte(EncodeSignature(sig)))
	m[sigRef] = []byte(EncodeSignature(sig))
	e.Signatures = []Signature{{Fingerprint(pub), sigRef}}
	leaf := HashLeaf([]byte(e.PayloadSHA256))
	rootDigest := "sha256:" + hex.EncodeToString(leaf[:])
	checkpointRef := put(m, Checkpoint{CheckpointAPIVersion, e.AuthorityID, 1, rootDigest})
	proofRef := put(m, InclusionProof{InclusionAPIVersion, 0, 1, []string{}})
	r := Receipt{TrustReceiptAPIVersion, e.AuthorityID, 1, e.PayloadSHA256, 1, 1, checkpointRef, "", ""}
	r.ReceiptDigest, _ = r.ComputeDigest()
	rawE, _ := json.Marshal(e)
	rawR, _ := json.Marshal(r)
	d := sha256.Sum256([]byte("descriptor"))
	descriptor := Descriptor{[]Anchor{{Fingerprint(pub), pub}}, 1, "sha256:" + hex.EncodeToString(d[:]), "synthetic-test"}
	v, err := NewVerifier(m, ClockFunc(func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.verifyOSSUnchecked(context.Background(), descriptor, Bundle{rawE, rawR, TransparencyEvidence{checkpointRef, proofRef, ""}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding().ID != ProfileOSS {
		t.Fatal("not OSS")
	}
}
func mustRaw(t *testing.T, value string) []byte {
	t.Helper()
	v, err := rawDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type testProtectedReader struct{ snapshot ProtectedSnapshot }

func (r testProtectedReader) CheckProtection(context.Context) error { return nil }
func (r testProtectedReader) Snapshot(context.Context) (ProtectedSnapshot, error) {
	return r.snapshot, nil
}

func newProtectedFixture(t *testing.T) (*Verifier, Descriptor, testProtectedReader, memoryEvidence) {
	t.Helper()
	anchorPrivate := ed25519.NewKeyFromSeed(bytes32("t2-anchor"))
	anchor := anchorPrivate.Public().(ed25519.PublicKey)
	rootPrivate := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	root := rootPrivate.Public().(ed25519.PublicKey)
	store := memoryEvidence{}
	keyRef := evidencecas.Digest([]byte(EncodePublicKey(root)))
	store[keyRef] = []byte(EncodePublicKey(root))
	e := Envelope{APIVersion: TrustRootsAPIVersion, AuthorityID: "t2-authority", Sequence: 1, Validity: Validity{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []RootKey{{Fingerprint(root), keyRef, "synthetic", "active"}}, Threshold: 1, RevocationEpoch: 1, Revocations: []Revocation{}}
	e.PayloadSHA256, _ = e.ComputePayloadSHA256()
	signature := ed25519.Sign(anchorPrivate, mustRaw(t, e.PayloadSHA256))
	signatureRef := evidencecas.Digest([]byte(EncodeSignature(signature)))
	store[signatureRef] = []byte(EncodeSignature(signature))
	e.Signatures = []Signature{{Fingerprint(anchor), signatureRef}}
	leaf := HashLeaf([]byte(e.PayloadSHA256))
	checkpointRef := put(store, Checkpoint{CheckpointAPIVersion, e.AuthorityID, 1, "sha256:" + hex.EncodeToString(leaf[:])})
	inclusionRef := put(store, InclusionProof{InclusionAPIVersion, 0, 1, []string{}})
	r := Receipt{TrustReceiptAPIVersion, e.AuthorityID, 1, e.PayloadSHA256, 1, 1, checkpointRef, "", ""}
	r.ReceiptDigest, _ = r.ComputeDigest()
	envelope, _ := json.Marshal(e)
	receipt, _ := json.Marshal(r)
	descriptor := Descriptor{[]Anchor{{Fingerprint(anchor), anchor}}, 1, digest(), "synthetic-test"}
	v, err := NewVerifier(store, ClockFunc(func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return v, descriptor, testProtectedReader{ProtectedSnapshot{envelope, receipt, TransparencyEvidence{checkpointRef, inclusionRef, ""}, false, "synthetic-protected", EvidenceProduction}}, store
}

func bytes32(label string) []byte {
	s := sha256.Sum256([]byte(label))
	return s[:]
}

type evidenceReaderFunc func(context.Context, string) ([]byte, error)

func (f evidenceReaderFunc) Read(ctx context.Context, digest string) ([]byte, error) {
	return f(ctx, digest)
}

func TestReadEvidenceBoundaryControls(t *testing.T) {
	good := []byte("synthetic evidence")
	goodDigest := evidencecas.Digest(good)
	if got, err := readEvidence(context.Background(), evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		return good, nil
	}), goodDigest); err != nil || string(got) != string(good) {
		t.Fatalf("valid evidence: %v", err)
	}
	if _, err := readEvidence(context.Background(), evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		return nil, nil
	}), goodDigest); !errors.Is(err, ErrEvidenceMissing) {
		t.Fatalf("missing evidence error = %v", err)
	}
	if _, err := readEvidence(context.Background(), evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		return []byte("different bytes"), nil
	}), goodDigest); !errors.Is(err, ErrEvidenceMismatch) {
		t.Fatalf("mismatched evidence error = %v", err)
	}
	large := make([]byte, maxEvidenceSize+1)
	largeDigest := evidencecas.Digest(large)
	if _, err := readEvidence(context.Background(), evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		return large, nil
	}), largeDigest); !errors.Is(err, ErrEvidenceOversize) {
		t.Fatalf("oversize evidence error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := readEvidence(ctx, evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		called = true
		return good, nil
	}), goodDigest); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-canceled evidence error = %v called=%v", err, called)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := readEvidence(ctx, evidenceReaderFunc(func(context.Context, string) ([]byte, error) {
		cancel()
		return good, nil
	}), goodDigest); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-read cancellation error = %v", err)
	}
}

func TestOrganizationAuthorityBindsExactReceiptDigest(t *testing.T) {
	v, descriptor, protected, _ := newProtectedFixture(t)
	first, err := v.verifyOrganizationUnchecked(context.Background(), descriptor, protected)
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(protected.snapshot.Receipt, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.PreviousReceiptDigest = digest()
	receipt.ReceiptDigest, _ = receipt.ComputeDigest()
	protected.snapshot.Receipt, _ = json.Marshal(receipt)
	second, err := v.verifyOrganizationUnchecked(context.Background(), descriptor, protected)
	if err != nil {
		t.Fatal(err)
	}
	if first.Binding().AuthoritySHA256 == second.Binding().AuthoritySHA256 {
		t.Fatal("protected receipt change did not change authority digest")
	}
}

func TestOrganizationAuthorityCannotUseOSSRotaion(t *testing.T) {
	v, descriptor, protected, _ := newProtectedFixture(t)
	current, err := v.verifyOrganizationUnchecked(context.Background(), descriptor, protected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.verifyRotationUnchecked(context.Background(), current, descriptor, Bundle{}); err != ErrDowngradeDenied {
		t.Fatalf("organization rotation error = %v, want %v", err, ErrDowngradeDenied)
	}
}

func TestVerifyDevelopmentAcceptsExplicitUnsignedInput(t *testing.T) {
	v, descriptor, protected, _ := newProtectedFixture(t)
	var envelope Envelope
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures = []Signature{}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.VerifyDevelopment(context.Background(), DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency})
	if err != nil {
		t.Fatalf("unsigned development input rejected: %v", err)
	}
	if got == nil || got.Binding().ID != ProfileDevelopment || got.Binding().Assurance != DevelopmentUnverified || got.Binding().EvidenceClass != EvidenceSimulated {
		t.Fatalf("unexpected development binding: %#v", got)
	}
	if _, err := v.verifyOSSUnchecked(context.Background(), descriptor, Bundle{Envelope: raw, Receipt: protected.snapshot.Receipt, Transparency: protected.snapshot.Transparency}); err == nil {
		t.Fatal("unsigned development input accepted as stable OSS")
	}
}

func TestVerifyDevelopmentRejectsMalformedInput(t *testing.T) {
	v, _, protected, _ := newProtectedFixture(t)
	var envelope map[string]any
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	delete(envelope, "signatures")
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyDevelopment(context.Background(), DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency}); err == nil {
		t.Fatal("development decoder accepted omitted signatures field")
	}
}

func TestVerifyDevelopmentSignedInputControls(t *testing.T) {
	v, _, protected, store := newProtectedFixture(t)
	var envelope Envelope
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	rootPrivate := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	signature := ed25519.Sign(rootPrivate, mustRaw(t, envelope.PayloadSHA256))
	signatureRef := evidencecas.Digest([]byte(EncodeSignature(signature)))
	store[signatureRef] = []byte(EncodeSignature(signature))
	envelope.Signatures = []Signature{{Fingerprint(rootPrivate.Public().(ed25519.PublicKey)), signatureRef}}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.VerifyDevelopment(context.Background(), DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency}); err != nil || got == nil {
		t.Fatalf("valid signed development input: got=%v err=%v", got, err)
	}
	badSignature := make([]byte, ed25519.SignatureSize)
	badRef := evidencecas.Digest([]byte(EncodeSignature(badSignature)))
	store[badRef] = []byte(EncodeSignature(badSignature))
	envelope.Signatures = []Signature{{Fingerprint(rootPrivate.Public().(ed25519.PublicKey)), badRef}}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.VerifyDevelopment(context.Background(), DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency}); got != nil || !errors.Is(err, ErrThreshold) {
		t.Fatalf("invalid signed development input: got=%v err=%v", got, err)
	}
}

func TestVerifyDevelopmentRejectsMalformedSignatureFields(t *testing.T) {
	v, _, protected, _ := newProtectedFixture(t)
	var envelope map[string]any
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"null":        nil,
		"non-array":   map[string]any{"keyFingerprint": "x"},
		"malformed":   []any{map[string]any{"keyFingerprint": "x"}},
		"unknown-key": []any{map[string]any{"keyFingerprint": digest(), "signatureCAS": digest(), "unknown": "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := make(map[string]any, len(envelope))
			for key, item := range envelope {
				doc[key] = item
			}
			doc["signatures"] = value
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := v.VerifyDevelopment(context.Background(), DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency}); got != nil || err == nil {
				t.Fatalf("malformed signatures accepted: got=%v err=%v", got, err)
			}
		})
	}
}

func TestVerifyDevelopmentRejectsNilOrZeroVerifierInputs(t *testing.T) {
	v, _, protected, store := newProtectedFixture(t)
	var envelope Envelope
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures = []Signature{}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	in := DevelopmentInputs{Envelope: raw, Transparency: protected.snapshot.Transparency}
	cases := map[string]func() (*DevelopmentContext, error){
		"nil verifier": func() (*DevelopmentContext, error) {
			var nilVerifier *Verifier
			return nilVerifier.VerifyDevelopment(context.Background(), in)
		},
		"zero verifier": func() (*DevelopmentContext, error) {
			return (&Verifier{}).VerifyDevelopment(context.Background(), in)
		},
		"nil clock": func() (*DevelopmentContext, error) {
			return (&Verifier{store: store}).VerifyDevelopment(context.Background(), in)
		},
		"nil store": func() (*DevelopmentContext, error) {
			return (&Verifier{clock: v.clock}).VerifyDevelopment(context.Background(), in)
		},
		"nil context": func() (*DevelopmentContext, error) {
			return v.VerifyDevelopment(nil, in)
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			var got *DevelopmentContext
			var callErr error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("panicked: %v", recovered)
					}
				}()
				got, callErr = call()
			}()
			if got != nil || callErr == nil {
				t.Fatalf("invalid verifier input accepted: got=%v err=%v", got, callErr)
			}
		})
	}
}
