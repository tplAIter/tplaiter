package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

type fixedExternalReader struct{ snapshot ProvisionedSnapshot }

func (r fixedExternalReader) Load(context.Context) (ProvisionedSnapshot, error) {
	return r.snapshot, nil
}

type externalReaderFunc func(context.Context) (ProvisionedSnapshot, error)

func (f externalReaderFunc) Load(ctx context.Context) (ProvisionedSnapshot, error) { return f(ctx) }

func externalFixture(t *testing.T, profile ProfileID) (*Verifier, *ExternalContext, Bundle, testProtectedReader) {
	t.Helper()
	v, legacy, protected, _ := newProtectedFixture(t)
	d := DescriptorDocument{APIVersion: DescriptorAPIVersion, Profile: profile, AuthorityID: "t2-authority", Threshold: legacy.Threshold, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "synthetic", SourceOrigin: "https://example.test/source", TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	for _, a := range legacy.Anchors {
		d.Anchors = append(d.Anchors, DescriptorAnchor{Fingerprint: a.Fingerprint, PublicKeyBase64: base64.StdEncoding.EncodeToString(a.PublicKey)})
	}
	d.DescriptorSHA256 = d.ComputedSHA256()
	draw, _ := json.Marshal(d)
	p := ProvisioningRecord{APIVersion: ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: d.DescriptorSHA256, AuthenticationEvidenceSHA256: digest(), EvidenceClass: EvidenceProduction}
	p.ProvisioningSHA256 = p.ComputedSHA256()
	praw, _ := json.Marshal(p)
	s := ProvisionedSnapshot{DescriptorJSON: draw, ProvisioningJSON: praw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256}
	if profile == ProfileOSS {
		e, err := DecodeEnvelope(protected.snapshot.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeReceipt(protected.snapshot.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		state := OSSAcceptedState{APIVersion: OSSAcceptedStateAPIVersion, DescriptorSHA256: d.DescriptorSHA256, ProvisioningSHA256: p.ProvisioningSHA256, AuthorityID: e.AuthorityID, Sequence: e.Sequence, EnvelopePayloadSHA256: e.PayloadSHA256, RevocationEpoch: e.RevocationEpoch, ReceiptDigest: r.ReceiptDigest, TreeSize: r.TreeSize, CheckpointDigest: r.CheckpointDigest}
		state.StateSHA256 = state.ComputedSHA256()
		s.OSSStateJSON, _ = json.Marshal(state)
		s.ExpectedOSSStateSHA256, s.InitialOSSStateSHA256 = state.StateSHA256, state.StateSHA256
	}
	ext, err := LoadExternal(context.Background(), fixedExternalReader{s})
	if err != nil {
		t.Fatal(err)
	}
	return v, ext, Bundle{Envelope: protected.snapshot.Envelope, Receipt: protected.snapshot.Receipt, Transparency: protected.snapshot.Transparency}, protected
}

func TestExternalOSSRequiresPinnedHeadAndMintsScopedAuthority(t *testing.T) {
	v, ext, candidate, _ := externalFixture(t, ProfileOSS)
	a, err := v.VerifyOSS(context.Background(), ext, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding().ID != ProfileOSS || a.Binding().ConfigSHA256 == "" {
		t.Fatal("missing scoped OSS binding")
	}
	if got := a.Binding().ConfigSHA256; got != "sha256:64de6976b49e0bc8b5ba082ccca6889c0550e21ccc543b98707d3328398e6ee6" {
		t.Fatalf("OSS effective config vector = %s", got)
	}
	if _, err := v.VerifyOSS(context.Background(), nil, candidate); !errors.Is(err, ErrExternalInvalid) {
		t.Fatalf("nil external context = %v", err)
	}
}

func TestLoadExternalRejectsMissingStateAndPinMismatch(t *testing.T) {
	_, ext, _, _ := externalFixture(t, ProfileOSS)
	if ext == nil {
		t.Fatal("fixture missing external context")
	}
	_, _, _, protected := externalFixture(t, ProfileOSS)
	if _, err := LoadExternal(context.Background(), fixedExternalReader{ProvisionedSnapshot{}}); !errors.Is(err, ErrExternalInvalid) {
		t.Fatalf("empty external snapshot = %v", err)
	}
	_ = protected
}

func TestExternalOrganizationDoesNotUseOSSState(t *testing.T) {
	v, ext, _, protected := externalFixture(t, ProfileOrganization)
	a, err := v.VerifyOrganization(context.Background(), ext, protected)
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding().ID != ProfileOrganization || a.Binding().EvidenceClass != EvidenceProduction {
		t.Fatal("invalid organization binding")
	}
	if got := a.Binding().ConfigSHA256; got != "sha256:7e9a1cd90773f84a89ab1de1ae8e51e40cbfe22300f42d701b68d3e3ce3d25cd" {
		t.Fatalf("organization effective config vector = %s", got)
	}
}

func TestExternalOrganizationRejectsSimulatedProvisioning(t *testing.T) {
	v, ext, _, protected := externalFixture(t, ProfileOrganization)
	draw, err := json.Marshal(ext.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	p := ext.provisioning
	p.EvidenceClass = EvidenceSimulated
	p.ProvisioningSHA256 = p.ComputedSHA256()
	praw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ProvisionedSnapshot{DescriptorJSON: draw, ProvisioningJSON: praw, ExpectedDescriptorSHA256: ext.descriptor.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256}
	simulated, err := LoadExternal(context.Background(), fixedExternalReader{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if simulated.provisioning.EvidenceClass != EvidenceSimulated {
		t.Fatal("external loader changed authenticated evidence class")
	}
	if _, err := v.VerifyOrganization(context.Background(), simulated, protected); !errors.Is(err, ErrExternalInvalid) {
		t.Fatalf("simulated organization provisioning = %v", err)
	}
	a, err := v.VerifyOrganization(context.Background(), ext, protected)
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding().EvidenceClass != EvidenceProduction {
		t.Fatal("production organization evidence class was not retained")
	}
}

func TestCompareStateRejectsRollbackCheckpointAndRefresh(t *testing.T) {
	_, ext, _, _ := externalFixture(t, ProfileOSS)
	s := ext.state
	e := Envelope{AuthorityID: s.AuthorityID, Sequence: s.Sequence - 1, RevocationEpoch: s.RevocationEpoch, PayloadSHA256: s.EnvelopePayloadSHA256}
	r := Receipt{ReceiptDigest: s.ReceiptDigest, TreeSize: s.TreeSize, CheckpointDigest: s.CheckpointDigest}
	if !errors.Is(compareState(s, e, r), ErrRollback) {
		t.Fatal("lower sequence accepted")
	}
	e.Sequence = s.Sequence + 1
	if !errors.Is(compareState(s, e, r), ErrRefreshRequired) {
		t.Fatal("advance did not require refresh")
	}
	e.Sequence, e.PayloadSHA256 = s.Sequence, digest()
	if !errors.Is(compareState(s, e, r), ErrCheckpointMismatch) {
		t.Fatal("changed equal head accepted")
	}
}

func snapshotFromContext(t *testing.T, ext *ExternalContext) ProvisionedSnapshot {
	t.Helper()
	d, _ := json.Marshal(ext.descriptor)
	p, _ := json.Marshal(ext.provisioning)
	s, _ := json.Marshal(ext.state)
	return ProvisionedSnapshot{DescriptorJSON: d, ProvisioningJSON: p, ExpectedDescriptorSHA256: ext.descriptor.DescriptorSHA256, ExpectedProvisioningSHA256: ext.provisioning.ProvisioningSHA256, OSSStateJSON: s, ExpectedOSSStateSHA256: ext.state.StateSHA256, InitialOSSStateSHA256: ext.initialStateSHA256}
}
func hashText(h MerkleHash) string { return "sha256:" + hex.EncodeToString(h[:]) }

func rotationNext(t *testing.T, v *Verifier, current Bundle) Bundle {
	return rotationNextAt(t, v, current, "2026-12-01T00:00:00Z", false)
}

func rotationNextAt(t *testing.T, v *Verifier, current Bundle, overlap string, recovery bool) Bundle {
	t.Helper()
	store := v.store.(memoryEvidence)
	old, err := DecodeEnvelope(current.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := DecodeReceipt(current.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := ed25519.NewKeyFromSeed(bytes32("t2-root"))
	newRoot := ed25519.NewKeyFromSeed(bytes32("t2-next-root"))
	pub := newRoot.Public().(ed25519.PublicKey)
	keyRef := evidencecas.Digest([]byte(EncodePublicKey(pub)))
	store[keyRef] = []byte(EncodePublicKey(pub))
	e := Envelope{APIVersion: TrustRootsAPIVersion, AuthorityID: old.AuthorityID, Sequence: old.Sequence + 1, Validity: old.Validity, AllowedPolicyOrigins: old.AllowedPolicyOrigins, RootKeys: []RootKey{{Fingerprint(pub), keyRef, "synthetic", "active"}}, Threshold: 1, RevocationEpoch: old.RevocationEpoch + 1, Revocations: []Revocation{}, Rotation: &Rotation{PreviousSequence: old.Sequence, OverlapUntil: overlap}}
	e.PayloadSHA256, _ = e.ComputePayloadSHA256()
	oldSig := ed25519.Sign(oldRoot, mustRaw(t, e.PayloadSHA256))
	newSig := ed25519.Sign(newRoot, mustRaw(t, e.PayloadSHA256))
	for _, x := range []struct {
		key ed25519.PublicKey
		sig []byte
	}{{oldRoot.Public().(ed25519.PublicKey), oldSig}, {pub, newSig}} {
		ref := evidencecas.Digest([]byte(EncodeSignature(x.sig)))
		store[ref] = []byte(EncodeSignature(x.sig))
		e.Signatures = append(e.Signatures, Signature{Fingerprint(x.key), ref})
	}
	if recovery {
		anchor := ed25519.NewKeyFromSeed(bytes32("t2-anchor"))
		sig := ed25519.Sign(anchor, mustRaw(t, e.PayloadSHA256))
		ref := evidencecas.Digest([]byte(EncodeSignature(sig)))
		store[ref] = []byte(EncodeSignature(sig))
		e.Signatures = append(e.Signatures, Signature{Fingerprint(anchor.Public().(ed25519.PublicKey)), ref})
	}
	for i := range e.Signatures {
		for j := i + 1; j < len(e.Signatures); j++ {
			if e.Signatures[j].KeyFingerprint < e.Signatures[i].KeyFingerprint {
				e.Signatures[i], e.Signatures[j] = e.Signatures[j], e.Signatures[i]
			}
		}
	}
	oldLeaf, newLeaf := HashLeaf([]byte(old.PayloadSHA256)), HashLeaf([]byte(e.PayloadSHA256))
	root := HashChildren(oldLeaf, newLeaf)
	checkpointRef := put(store, Checkpoint{CheckpointAPIVersion, e.AuthorityID, 2, hashText(root)})
	inclusionRef := put(store, InclusionProof{InclusionAPIVersion, 1, 2, []string{hashText(oldLeaf)}})
	consistencyRef := put(store, ConsistencyProof{ConsistencyAPIVersion, 1, 2, []string{hashText(newLeaf)}})
	r := Receipt{APIVersion: TrustReceiptAPIVersion, AuthorityID: e.AuthorityID, HighestAcceptedSequence: e.Sequence, EnvelopePayloadSHA256: e.PayloadSHA256, RevocationEpoch: e.RevocationEpoch, TreeSize: 2, CheckpointDigest: checkpointRef, PreviousReceiptDigest: oldReceipt.ReceiptDigest}
	r.ReceiptDigest, _ = r.ComputeDigest()
	rawE, _ := json.Marshal(e)
	rawR, _ := json.Marshal(r)
	return Bundle{Envelope: rawE, Receipt: rawR, Transparency: TransparencyEvidence{CheckpointCAS: checkpointRef, InclusionProofCAS: inclusionRef, ConsistencyProofCAS: consistencyRef}}
}

func TestPrepareOSSRefreshProposalCASReload(t *testing.T) {
	v, ext, current, _ := externalFixture(t, ProfileOSS)
	next := rotationNext(t, v, current)
	p, err := v.PrepareOSSRefresh(context.Background(), ext, current, next)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ExpectedStateSHA256(); got != ext.state.StateSHA256 {
		t.Fatalf("proposal expected %s", got)
	}
	if _, err := v.VerifyOSS(context.Background(), ext, next); !errors.Is(err, ErrRefreshRequired) {
		t.Fatalf("uncommitted next = %v", err)
	}
	if ext.state.Sequence != 1 {
		t.Fatal("prepare mutated retained context")
	}
	snap := snapshotFromContext(t, ext)
	compareAndSwap := func(expected string) bool { return expected == snap.ExpectedOSSStateSHA256 }
	if compareAndSwap(digest()) {
		t.Fatal("stale synthetic CAS expectation accepted")
	}
	if !compareAndSwap(p.ExpectedStateSHA256()) {
		t.Fatal("current synthetic CAS expectation rejected")
	}
	snap.OSSStateJSON = p.NextStateJSON()
	state, err := DecodeOSSAcceptedState(snap.OSSStateJSON)
	if err != nil {
		t.Fatal(err)
	}
	snap.ExpectedOSSStateSHA256 = state.StateSHA256
	reloaded, err := LoadExternal(context.Background(), fixedExternalReader{snap})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyOSS(context.Background(), reloaded, current); !errors.Is(err, ErrRollback) {
		t.Fatalf("old head after reload = %v", err)
	}
	if _, err := v.VerifyOSS(context.Background(), reloaded, next); err != nil {
		t.Fatal(err)
	}
}

func TestLoadExternalRetainedPinsAndCopies(t *testing.T) {
	v, ext, candidate, _ := externalFixture(t, ProfileOSS)
	first, err := v.VerifyOSS(context.Background(), ext, candidate)
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshotFromContext(t, ext)
	for _, mutate := range []func(*ProvisionedSnapshot){func(s *ProvisionedSnapshot) { s.InitialOSSStateSHA256 = "" }, func(s *ProvisionedSnapshot) { s.ExpectedOSSStateSHA256 = digest() }} {
		bad := snap
		mutate(&bad)
		if _, err := LoadExternal(context.Background(), fixedExternalReader{bad}); !errors.Is(err, ErrExternalInvalid) {
			t.Fatalf("bad pin accepted: %v", err)
		}
	}
	changed := snap
	changed.InitialOSSStateSHA256 = digest()
	changedExt, err := LoadExternal(context.Background(), fixedExternalReader{changed})
	if err != nil {
		t.Fatal(err)
	}
	if changedExt.initialStateSHA256 == ext.initialStateSHA256 {
		t.Fatal("initial-state pin substitution was ignored")
	}
	before := ext.descriptor.DescriptorSHA256
	snap.DescriptorJSON[0] ^= 1
	snap.ProvisioningJSON[0] ^= 1
	snap.OSSStateJSON[0] ^= 1
	if ext.descriptor.DescriptorSHA256 != before || ext.provisioning.ProvisioningSHA256 == "" || ext.state.StateSHA256 == "" {
		t.Fatal("context aliased caller bytes")
	}
	if got, err := v.VerifyOSS(context.Background(), ext, candidate); err != nil || got.Binding() != first.Binding() {
		t.Fatalf("caller mutation changed loaded context: authority=%v err=%v", got, err)
	}
}

func TestLoadExternalCancellationPropagates(t *testing.T) {
	_, ext, _, _ := externalFixture(t, ProfileOSS)
	snap := snapshotFromContext(t, ext)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := LoadExternal(ctx, externalReaderFunc(func(context.Context) (ProvisionedSnapshot, error) {
		called = true
		return snap, nil
	})); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-reader cancellation: err=%v called=%v", err, called)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := LoadExternal(ctx, externalReaderFunc(func(got context.Context) (ProvisionedSnapshot, error) {
		if got != ctx {
			t.Fatal("reader received a different context")
		}
		cancel()
		return snap, nil
	})); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-reader cancellation: %v", err)
	}
}

func TestExternalDescriptorAndProvisioningPinsChangeBinding(t *testing.T) {
	v, ext, candidate, _ := externalFixture(t, ProfileOSS)
	first, err := v.VerifyOSS(context.Background(), ext, candidate)
	if err != nil {
		t.Fatal(err)
	}
	d := ext.descriptor
	d.PublisherScopes = append([]PublisherScope(nil), d.PublisherScopes...)
	d.PublisherScopes[0].TemplatePath = "templates/base"
	d.DescriptorSHA256 = d.ComputedSHA256()
	p := ext.provisioning
	p.DescriptorSHA256 = d.DescriptorSHA256
	p.Mode = "release-distribution"
	p.ProvisioningSHA256 = p.ComputedSHA256()
	s := ext.state
	s.DescriptorSHA256 = d.DescriptorSHA256
	s.ProvisioningSHA256 = p.ProvisioningSHA256
	s.StateSHA256 = s.ComputedSHA256()
	draw, _ := json.Marshal(d)
	praw, _ := json.Marshal(p)
	sraw, _ := json.Marshal(s)
	changed, err := LoadExternal(context.Background(), fixedExternalReader{ProvisionedSnapshot{DescriptorJSON: draw, ProvisioningJSON: praw, ExpectedDescriptorSHA256: d.DescriptorSHA256, ExpectedProvisioningSHA256: p.ProvisioningSHA256, OSSStateJSON: sraw, ExpectedOSSStateSHA256: s.StateSHA256, InitialOSSStateSHA256: s.StateSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.VerifyOSS(context.Background(), changed, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if first.Binding().ConfigSHA256 == second.Binding().ConfigSHA256 || first.Binding().AuthoritySHA256 == second.Binding().AuthoritySHA256 {
		t.Fatal("same-key external pin substitution did not change binding")
	}
}

func TestPrepareOSSRefreshRejectsWrongContextAndBrokenProposal(t *testing.T) {
	v, ext, current, _ := externalFixture(t, ProfileOSS)
	next := rotationNext(t, v, current)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, Bundle{}); err == nil {
		t.Fatal("empty non-rotation accepted")
	}
	_, org, _, _ := externalFixture(t, ProfileOrganization)
	if _, err := v.PrepareOSSRefresh(context.Background(), org, current, next); !errors.Is(err, ErrExternalInvalid) {
		t.Fatalf("organization refresh = %v", err)
	}
	var widened Envelope
	if err := json.Unmarshal(next.Envelope, &widened); err != nil {
		t.Fatal(err)
	}
	widened.AllowedPolicyOrigins = append(widened.AllowedPolicyOrigins, "https://example.test/widened")
	widened.PayloadSHA256, _ = widened.ComputePayloadSHA256()
	widenedRaw, _ := json.Marshal(widened)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, Bundle{Envelope: widenedRaw, Receipt: next.Receipt, Transparency: next.Transparency}); !errors.Is(err, ErrReceiptBinding) {
		t.Fatalf("candidate scope widening = %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(next.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	env.Signatures = env.Signatures[1:]
	next.Envelope, _ = json.Marshal(env)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, next); err == nil {
		t.Fatal("missing old quorum accepted")
	}
	if ext.state.Sequence != 1 {
		t.Fatal("rejected proposal mutated retained state")
	}
}

func TestPrepareOSSRefreshRecoveryAndConsistencyLinkageDenials(t *testing.T) {
	v, ext, current, _ := externalFixture(t, ProfileOSS)
	recovery := rotationNextAt(t, v, current, "2026-01-01T00:00:00Z", true)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, recovery); err != nil {
		t.Fatalf("recovery quorum = %v", err)
	}
	var recoveryEnv Envelope
	if err := json.Unmarshal(recovery.Envelope, &recoveryEnv); err != nil {
		t.Fatal(err)
	}
	anchor := ed25519.NewKeyFromSeed(bytes32("t2-anchor")).Public().(ed25519.PublicKey)
	recoveryEnv.Signatures = filterSignatures(recoveryEnv.Signatures, Fingerprint(anchor))
	recovery.Envelope, _ = json.Marshal(recoveryEnv)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, recovery); err == nil {
		t.Fatal("missing recovery quorum accepted")
	}
	next := rotationNext(t, v, current)
	var nextEnv Envelope
	if err := json.Unmarshal(next.Envelope, &nextEnv); err != nil {
		t.Fatal(err)
	}
	oldRoot := ed25519.NewKeyFromSeed(bytes32("t2-root")).Public().(ed25519.PublicKey)
	nextEnv.Signatures = filterSignatures(nextEnv.Signatures, Fingerprint(oldRoot))
	missingNew, _ := json.Marshal(nextEnv)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, Bundle{Envelope: missingNew, Receipt: next.Receipt, Transparency: next.Transparency}); err == nil {
		t.Fatal("missing new quorum accepted")
	}
	var receipt Receipt
	if err := json.Unmarshal(next.Receipt, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.PreviousReceiptDigest = digest()
	receipt.ReceiptDigest, _ = receipt.ComputeDigest()
	wrongPrevious, _ := json.Marshal(receipt)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, Bundle{Envelope: next.Envelope, Receipt: wrongPrevious, Transparency: next.Transparency}); err == nil {
		t.Fatal("wrong previous receipt accepted")
	}
	bad := next
	bad.Transparency.ConsistencyProofCAS = digest()
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, bad); err == nil {
		t.Fatal("bad consistency accepted")
	}
	var env Envelope
	if err := json.Unmarshal(next.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	env.Rotation.PreviousSequence = 0
	env.PayloadSHA256, _ = env.ComputePayloadSHA256()
	raw, _ := json.Marshal(env)
	if _, err := v.PrepareOSSRefresh(context.Background(), ext, current, Bundle{Envelope: raw, Receipt: next.Receipt, Transparency: next.Transparency}); err == nil {
		t.Fatal("bad linkage accepted")
	}
	if _, err := v.VerifyOSS(context.Background(), nil, next); !errors.Is(err, ErrExternalInvalid) {
		t.Fatalf("candidate-owned history fallback = %v", err)
	}
	if ext.state.Sequence != 1 {
		t.Fatal("rejected refresh changed retained context")
	}
}

func filterSignatures(in []Signature, fingerprint string) []Signature {
	out := make([]Signature, 0, len(in)-1)
	for _, signature := range in {
		if signature.KeyFingerprint != fingerprint {
			out = append(out, signature)
		}
	}
	return out
}

func TestInitialPinChangesEffectiveConfigurationIdentity(t *testing.T) {
	v, ext, current, _ := externalFixture(t, ProfileOSS)
	next := rotationNextAt(t, v, current, "2026-01-01T00:00:00Z", true)
	p, err := v.PrepareOSSRefresh(context.Background(), ext, current, next)
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshotFromContext(t, ext)
	snap.OSSStateJSON = p.NextStateJSON()
	state, err := DecodeOSSAcceptedState(snap.OSSStateJSON)
	if err != nil {
		t.Fatal(err)
	}
	snap.ExpectedOSSStateSHA256 = state.StateSHA256
	snap.InitialOSSStateSHA256 = state.StateSHA256
	anchored, err := LoadExternal(context.Background(), fixedExternalReader{snap})
	if err != nil {
		t.Fatal(err)
	}
	rotated := snap
	rotated.InitialOSSStateSHA256 = ext.initialStateSHA256
	rotatedHead, err := LoadExternal(context.Background(), fixedExternalReader{rotated})
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.VerifyOSS(context.Background(), anchored, next)
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.VerifyOSS(context.Background(), rotatedHead, next)
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding().ConfigSHA256 == b.Binding().ConfigSHA256 {
		t.Fatal("initial-state pin change did not change configuration identity")
	}
	proposalBytes := p.NextStateJSON()
	proposalBytes[0] ^= 1
	if got := p.NextStateJSON(); len(got) == 0 || got[0] == proposalBytes[0] {
		t.Fatal("proposal state accessor returned an aliased slice")
	}
}
