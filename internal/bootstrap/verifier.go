package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"time"
)

var (
	ErrRollback         = errors.New("bootstrap: TRUST_ROLLBACK")
	ErrUncommitted      = errors.New("bootstrap: TRUST_UNCOMMITTED")
	ErrSelfRoot         = errors.New("bootstrap: TRUST_SELF_ROOT")
	ErrThreshold        = errors.New("bootstrap: signature threshold not met")
	ErrExpired          = errors.New("bootstrap: TRUST_EXPIRED")
	ErrRevoked          = errors.New("bootstrap: TRUST_REVOKED")
	ErrReceiptBinding   = errors.New("bootstrap: protected receipt binding mismatch")
	ErrEvidenceMissing  = errors.New("bootstrap: evidence missing")
	ErrEvidenceMismatch = errors.New("bootstrap: evidence digest mismatch")
	ErrEvidenceOversize = errors.New("bootstrap: evidence exceeds size limit")
)

const maxEvidenceSize = 16 << 20

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Anchor struct {
	Fingerprint string
	PublicKey   ed25519.PublicKey
}

// Descriptor is independently provisioned public bootstrap material. Candidate metadata never supplies it.
type Descriptor struct {
	Anchors      []Anchor
	Threshold    uint32
	Digest       string
	Provisioning string
}

func (d Descriptor) validate() error {
	if !validDigest(d.Digest) || d.Threshold == 0 || int(d.Threshold) > len(d.Anchors) || d.Provisioning == "" {
		return ErrSelfRoot
	}
	seen := map[string]bool{}
	for _, a := range d.Anchors {
		if len(a.PublicKey) != ed25519.PublicKeySize || a.Fingerprint != Fingerprint(a.PublicKey) || seen[a.Fingerprint] {
			return ErrSelfRoot
		}
		seen[a.Fingerprint] = true
	}
	return nil
}

type Bundle struct {
	Envelope     []byte
	Receipt      []byte
	Transparency TransparencyEvidence
}
type DevelopmentInputs struct {
	Envelope     []byte
	Transparency TransparencyEvidence
}
type AuthoritySnapshot struct {
	AuthorityID           string
	Sequence              uint64
	EnvelopePayloadSHA256 string
	ReceiptDigest         string
	RevocationEpoch       uint64
	TreeSize              uint64
	CheckpointDigest      string
}
type Authority struct {
	envelope        Envelope
	receipt         Receipt
	checkpoint      Checkpoint
	keys            map[string]ed25519.PublicKey
	binding         ProfileBinding
	publisherScopes []PublisherScope
}
type DevelopmentContext struct {
	snapshot AuthoritySnapshot
	binding  ProfileBinding
}

func (a *Authority) Snapshot() AuthoritySnapshot {
	if a == nil {
		return AuthoritySnapshot{}
	}
	return AuthoritySnapshot{a.receipt.AuthorityID, a.receipt.HighestAcceptedSequence, a.receipt.EnvelopePayloadSHA256, a.receipt.ReceiptDigest, a.receipt.RevocationEpoch, a.receipt.TreeSize, a.receipt.CheckpointDigest}
}
func (a *Authority) Binding() ProfileBinding {
	if a == nil {
		return ProfileBinding{}
	}
	return a.binding
}
func (a *DevelopmentContext) Binding() ProfileBinding {
	if a == nil {
		return ProfileBinding{}
	}
	return a.binding
}
func (a *DevelopmentContext) Snapshot() AuthoritySnapshot {
	if a == nil {
		return AuthoritySnapshot{}
	}
	return a.snapshot
}
func (a *Authority) AllowsPolicyOrigin(s string) bool {
	if a == nil {
		return false
	}
	for _, v := range a.envelope.AllowedPolicyOrigins {
		if v == s {
			return true
		}
	}
	return false
}

type Verifier struct {
	store evidencecas.Reader
	clock Clock
}

func NewVerifier(store evidencecas.Reader, clock Clock, legacyAnchors []Anchor, legacyThreshold uint32) (*Verifier, error) {
	if store == nil || clock == nil {
		return nil, errors.New("bootstrap: evidence store and clock are required")
	}
	return &Verifier{store, clock}, nil
}

// verifyOSSUnchecked is retained only as an internal compatibility helper for
// legacy tests. New OSS verification must enter through ExternalContext.
func (v *Verifier) verifyOSSUnchecked(ctx context.Context, d Descriptor, b Bundle) (*Authority, error) {
	if e := d.validate(); e != nil {
		return nil, e
	}
	return v.verify(ctx, d, b, nil, ProfileOSS, EvidenceProduction)
}
func (v *Verifier) verifyOrganizationUnchecked(ctx context.Context, d Descriptor, b ProtectedReader) (*Authority, error) {
	if e := d.validate(); e != nil {
		return nil, e
	}
	s, e := protectedSnapshot(ctx, b)
	if e != nil {
		return nil, e
	}
	return v.verify(ctx, d, Bundle{Envelope: s.Envelope, Receipt: s.Receipt, Transparency: s.Transparency}, &s, ProfileOrganization, EvidenceProduction)
}
func (v *Verifier) VerifyDevelopment(ctx context.Context, in DevelopmentInputs) (*DevelopmentContext, error) {
	if ctx == nil || v == nil || v.store == nil || v.clock == nil {
		return nil, errors.New("bootstrap: development verifier, evidence store, clock, and context are required")
	}
	e, err := decodeDevelopmentEnvelope(in.Envelope)
	if err != nil {
		return nil, err
	}
	if err = e.VerifyPayloadSHA256(); err != nil {
		return nil, err
	}
	lo, hi, _ := e.Validity.bounds()
	if now := v.clock.Now().UTC(); now.Before(lo) || !now.Before(hi) {
		return nil, ErrExpired
	}
	// Unsigned development material is explicitly unverified. If signing
	// evidence is present, retain the normal verification checks; accepting
	// the unsigned form must not weaken signed development inputs.
	if len(e.Signatures) > 0 {
		keys, err := v.loadKeys(ctx, e)
		if err != nil {
			return nil, err
		}
		if err = v.threshold(ctx, e, keys, e.Threshold); err != nil {
			return nil, err
		}
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, Receipt{AuthorityID: e.AuthorityID, TreeSize: 1, CheckpointDigest: in.Transparency.CheckpointCAS}, in.Transparency)
	if err != nil {
		return nil, err
	}
	ad, _ := DomainDigest("tplaiter.dev/development-authority/v1", struct {
		ID       string `json:"id"`
		Sequence uint64 `json:"sequence"`
		Payload  string `json:"payload"`
	}{e.AuthorityID, e.Sequence, e.PayloadSHA256})
	p := ProfileBinding{ProfileBindingAPIVersion, ProfileDevelopment, 1, ad, ad, ad, DevelopmentUnverified, EvidenceSimulated}
	return &DevelopmentContext{AuthoritySnapshot{e.AuthorityID, e.Sequence, e.PayloadSHA256, "", e.RevocationEpoch, c.TreeSize, in.Transparency.CheckpointCAS}, p}, nil
}

// VerifyRotation requires an already verified authority.  A candidate cannot
// turn its own replacement keys into a root: during overlap both quorums sign;
// after it, the independently provisioned recovery descriptor signs.
func (v *Verifier) verifyRotationUnchecked(ctx context.Context, current *Authority, recovery Descriptor, next Bundle) (*Authority, error) {
	if current == nil {
		return nil, ErrReceiptBinding
	}
	if current.binding.ID != ProfileOSS {
		return nil, ErrDowngradeDenied
	}
	if err := recovery.validate(); err != nil {
		return nil, err
	}
	e, r, err := v.decode(next)
	if err != nil {
		return nil, err
	}
	old := current.Snapshot()
	if e.AuthorityID != old.AuthorityID || e.Sequence <= old.Sequence || e.Rotation == nil || e.Rotation.PreviousSequence != old.Sequence {
		return nil, ErrRollback
	}
	if r.PreviousReceiptDigest != old.ReceiptDigest || r.RevocationEpoch < old.RevocationEpoch || r.TreeSize < old.TreeSize {
		return nil, ErrReceiptBinding
	}
	keys, err := v.loadKeys(ctx, e)
	if err != nil {
		return nil, err
	}
	overlap, err := parseTime(e.Rotation.OverlapUntil)
	if err != nil {
		return nil, err
	}
	if !v.clock.Now().UTC().After(overlap) {
		if err := v.threshold(ctx, e, current.keys, current.envelope.Threshold); err != nil {
			return nil, fmt.Errorf("bootstrap: old rotation quorum: %w", err)
		}
		if err := v.threshold(ctx, e, eligible(*e, keys), e.Threshold); err != nil {
			return nil, fmt.Errorf("bootstrap: new rotation quorum: %w", err)
		}
	} else if err := v.threshold(ctx, e, mapAnchors(recovery.Anchors), recovery.Threshold); err != nil {
		return nil, fmt.Errorf("bootstrap: recovery quorum: %w", err)
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, *r, next.Transparency)
	if err != nil {
		return nil, err
	}
	if err := v.verifyConsistency(ctx, current.checkpoint, c, next.Transparency.ConsistencyProofCAS); err != nil {
		return nil, err
	}
	payload := struct {
		Descriptor string `json:"descriptor"`
		ID         string `json:"id"`
		Sequence   uint64 `json:"sequence"`
		Payload    string `json:"payload"`
		Epoch      uint64 `json:"epoch"`
		Checkpoint string `json:"checkpoint"`
	}{recovery.Digest, e.AuthorityID, e.Sequence, e.PayloadSHA256, e.RevocationEpoch, r.CheckpointDigest}
	digest, _ := DomainDigest("tplaiter.dev/authority/v1", payload)
	return &Authority{envelope: *e, receipt: *r, checkpoint: c, keys: eligible(*e, keys), binding: ProfileBinding{APIVersion: ProfileBindingAPIVersion, ID: ProfileOSS, DefinitionVersion: 1, ConfigSHA256: recovery.Digest, PolicySHA256: e.PayloadSHA256, AuthoritySHA256: digest, Assurance: PublisherVerified, EvidenceClass: EvidenceProduction}}, nil
}

func (v *Verifier) verifyConsistency(ctx context.Context, old, next Checkpoint, proofRef string) error {
	if !validDigest(proofRef) {
		return errors.New("bootstrap: missing transparency consistency proof")
	}
	raw, err := readEvidence(ctx, v.store, proofRef)
	if err != nil {
		return err
	}
	var proof ConsistencyProof
	if err := canonicaljson.DecodeStrict(raw, &proof); err != nil {
		return err
	}
	if proof.APIVersion != ConsistencyAPIVersion || proof.OldTreeSize != old.TreeSize || proof.NewTreeSize != next.TreeSize || proof.Hashes == nil {
		return errors.New("bootstrap: consistency proof metadata mismatch")
	}
	hashes := make([]MerkleHash, len(proof.Hashes))
	for i, x := range proof.Hashes {
		if hashes[i], err = merkleHash(x); err != nil {
			return err
		}
	}
	a, err := merkleHash(old.RootHash)
	if err != nil {
		return err
	}
	b, err := merkleHash(next.RootHash)
	if err != nil {
		return err
	}
	return VerifyConsistency(old.TreeSize, next.TreeSize, a, b, hashes)
}
func (v *Verifier) verify(ctx context.Context, d Descriptor, b Bundle, protected *ProtectedSnapshot, id ProfileID, class EvidenceClass) (*Authority, error) {
	e, r, err := v.decode(b)
	if err != nil {
		return nil, err
	}
	if err = v.threshold(ctx, e, mapAnchors(d.Anchors), d.Threshold); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfRoot, err)
	}
	keys, err := v.loadKeys(ctx, e)
	if err != nil {
		return nil, err
	}
	if len(eligible(*e, keys)) < int(e.Threshold) {
		return nil, ErrRevoked
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, *r, b.Transparency)
	if err != nil {
		return nil, err
	}
	payload := struct {
		Descriptor string `json:"descriptor"`
		ID         string `json:"id"`
		Sequence   uint64 `json:"sequence"`
		Payload    string `json:"payload"`
		Epoch      uint64 `json:"epoch"`
		Checkpoint string `json:"checkpoint"`
		Backend    string `json:"backend,omitempty"`
		Receipt    string `json:"receiptDigest,omitempty"`
	}{d.Digest, e.AuthorityID, e.Sequence, e.PayloadSHA256, e.RevocationEpoch, r.CheckpointDigest, "", ""}
	if protected != nil {
		payload.Backend = protected.BackendID
		payload.Receipt = r.ReceiptDigest
	}
	ad, _ := DomainDigest("tplaiter.dev/authority/v1", payload)
	a := PublisherVerified
	if id == ProfileOrganization {
		a = OrganizationProtected
	}
	p := ProfileBinding{ProfileBindingAPIVersion, id, 1, d.Digest, e.PayloadSHA256, ad, a, class}
	return &Authority{envelope: *e, receipt: *r, checkpoint: c, keys: eligible(*e, keys), binding: p}, nil
}
func (v *Verifier) decode(b Bundle) (*Envelope, *Receipt, error) {
	e, x := DecodeEnvelope(b.Envelope)
	if x != nil {
		return nil, nil, x
	}
	r, x := DecodeReceipt(b.Receipt)
	if x != nil {
		return nil, nil, x
	}
	if x = e.VerifyPayloadSHA256(); x != nil {
		return nil, nil, x
	}
	if x = r.VerifyDigest(); x != nil {
		return nil, nil, x
	}
	if e.Sequence < r.HighestAcceptedSequence {
		return nil, nil, ErrRollback
	}
	if e.Sequence > r.HighestAcceptedSequence {
		return nil, nil, ErrUncommitted
	}
	if e.AuthorityID != r.AuthorityID || e.PayloadSHA256 != r.EnvelopePayloadSHA256 || e.RevocationEpoch != r.RevocationEpoch {
		return nil, nil, ErrReceiptBinding
	}
	lo, hi, _ := e.Validity.bounds()
	now := v.clock.Now().UTC()
	if now.Before(lo) || !now.Before(hi) {
		return nil, nil, ErrExpired
	}
	return e, r, nil
}
func mapAnchors(a []Anchor) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, x := range a {
		m[x.Fingerprint] = x.PublicKey
	}
	return m
}
func (v *Verifier) loadKeys(ctx context.Context, e *Envelope) (map[string]ed25519.PublicKey, error) {
	m := map[string]ed25519.PublicKey{}
	for _, x := range e.RootKeys {
		b, err := readEvidence(ctx, v.store, x.PublicKeyCAS)
		if err != nil {
			return nil, err
		}
		k, err := DecodePublicKey(b)
		if err != nil || Fingerprint(k) != x.Fingerprint {
			return nil, errors.New("bootstrap: public key fingerprint mismatch")
		}
		m[x.Fingerprint] = k
	}
	return m, nil
}
func (v *Verifier) threshold(ctx context.Context, e *Envelope, keys map[string]ed25519.PublicKey, want uint32) error {
	msg, err := rawDigest(e.PayloadSHA256)
	if err != nil {
		return err
	}
	var n uint32
	for _, s := range e.Signatures {
		k, ok := keys[s.KeyFingerprint]
		if !ok {
			continue
		}
		b, er := readEvidence(ctx, v.store, s.SignatureCAS)
		if er != nil {
			return er
		}
		sig, er := DecodeSignature(b)
		if er != nil {
			return er
		}
		if ed25519.Verify(k, msg, sig) {
			n++
		}
	}
	if n < want {
		return ErrThreshold
	}
	return nil
}

func readEvidence(ctx context.Context, store evidencecas.Reader, digest string) ([]byte, error) {
	if store == nil {
		return nil, ErrEvidenceMissing
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("bootstrap: evidence read canceled: %w", err)
	}
	if !validDigest(digest) {
		return nil, fmt.Errorf("%w: invalid reference", ErrEvidenceMismatch)
	}
	raw, err := store.Read(ctx, digest)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("bootstrap: evidence read canceled: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("%w: %s", ErrEvidenceMissing, digest)
	}
	if len(raw) > maxEvidenceSize {
		return nil, fmt.Errorf("%w: %s", ErrEvidenceOversize, digest)
	}
	if evidencecas.Digest(raw) != digest {
		return nil, fmt.Errorf("%w: %s", ErrEvidenceMismatch, digest)
	}
	return raw, nil
}
func eligible(e Envelope, keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for f, k := range keys {
		if !revoked(e, f) {
			out[f] = k
		}
	}
	return out
}
func revoked(e Envelope, f string) bool {
	for _, r := range e.Revocations {
		if r.Fingerprint == f && r.EffectiveSequence <= e.Sequence {
			return true
		}
	}
	return false
}
