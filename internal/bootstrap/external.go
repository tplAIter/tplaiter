package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrRefreshRequired    = errors.New("bootstrap: TRUST_REFRESH_REQUIRED")
	ErrCheckpointMismatch = errors.New("bootstrap: TRUST_CHECKPOINT_MISMATCH")
	ErrExternalInvalid    = errors.New("bootstrap: TRUST_EXTERNAL_INVALID")
)

// ExternalAuthorityReader is a composition-owned port. Its provenance and
// persistence guarantees are trusted inputs; this package never selects files
// or derives an accepted pin from a candidate bundle.
type ExternalAuthorityReader interface {
	Load(context.Context) (ProvisionedSnapshot, error)
}

type ProvisionedSnapshot struct {
	DescriptorJSON             []byte
	ProvisioningJSON           []byte
	ExpectedDescriptorSHA256   string
	ExpectedProvisioningSHA256 string
	OSSStateJSON               []byte
	ExpectedOSSStateSHA256     string
	InitialOSSStateSHA256      string
}

// ExternalContext has no public constructor. It holds validated copies only.
type ExternalContext struct {
	descriptor         DescriptorDocument
	provisioning       ProvisioningRecord
	state              OSSAcceptedState
	hasState           bool
	initialStateSHA256 string
}

func LoadExternal(ctx context.Context, reader ExternalAuthorityReader) (*ExternalContext, error) {
	if reader == nil || ctx == nil {
		return nil, ErrExternalInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := reader.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: reader: %v", ErrExternalInvalid, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := DecodeDescriptorDocument(append([]byte(nil), s.DescriptorJSON...))
	if err != nil || d.DescriptorSHA256 != s.ExpectedDescriptorSHA256 {
		return nil, ErrExternalInvalid
	}
	p, err := DecodeProvisioningRecord(append([]byte(nil), s.ProvisioningJSON...))
	if err != nil || p.ProvisioningSHA256 != s.ExpectedProvisioningSHA256 || p.DescriptorSHA256 != d.DescriptorSHA256 {
		return nil, ErrExternalInvalid
	}
	ext := &ExternalContext{descriptor: cloneDescriptor(*d), provisioning: *p, initialStateSHA256: s.InitialOSSStateSHA256}
	if d.Profile == ProfileOrganization {
		if len(s.OSSStateJSON) != 0 || s.ExpectedOSSStateSHA256 != "" || s.InitialOSSStateSHA256 != "" {
			return nil, ErrExternalInvalid
		}
		return ext, nil
	}
	if d.Profile != ProfileOSS || !validDigest(s.ExpectedOSSStateSHA256) || !validDigest(s.InitialOSSStateSHA256) || len(s.OSSStateJSON) == 0 {
		return nil, ErrExternalInvalid
	}
	state, err := DecodeOSSAcceptedState(append([]byte(nil), s.OSSStateJSON...))
	if err != nil || state.StateSHA256 != s.ExpectedOSSStateSHA256 || state.DescriptorSHA256 != d.DescriptorSHA256 || state.ProvisioningSHA256 != p.ProvisioningSHA256 || state.AuthorityID != d.AuthorityID {
		return nil, ErrExternalInvalid
	}
	ext.state, ext.hasState = *state, true
	return ext, nil
}

func cloneDescriptor(d DescriptorDocument) DescriptorDocument {
	d.Anchors = append([]DescriptorAnchor(nil), d.Anchors...)
	d.AllowedPolicyOrigins = append([]string(nil), d.AllowedPolicyOrigins...)
	d.PublisherScopes = append([]PublisherScope(nil), d.PublisherScopes...)
	return d
}

func (v *Verifier) VerifyOSS(ctx context.Context, ext *ExternalContext, candidate Bundle) (*Authority, error) {
	if v == nil || ext == nil || !ext.hasState || ext.descriptor.Profile != ProfileOSS {
		return nil, ErrExternalInvalid
	}
	e, r, err := v.decode(candidate)
	if err != nil {
		return nil, err
	}
	if err := ext.descriptor.scope(*e); err != nil {
		return nil, err
	}
	if err := compareState(ext.state, *e, *r); err != nil {
		return nil, err
	}
	keys, err := v.loadKeys(ctx, e)
	if err != nil {
		return nil, err
	}
	if ext.state.StateSHA256 == ext.initialStateSHA256 {
		if err := v.threshold(ctx, e, descriptorAnchors(ext.descriptor), ext.descriptor.Threshold); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSelfRoot, err)
		}
	} else if err := v.threshold(ctx, e, eligible(*e, keys), e.Threshold); err != nil {
		return nil, err
	}
	if len(eligible(*e, keys)) < int(e.Threshold) {
		return nil, ErrRevoked
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, *r, candidate.Transparency)
	if err != nil {
		return nil, err
	}
	return ext.authority(*e, *r, c, eligible(*e, keys), ext.provisioning.EvidenceClass, "", "")
}

func (v *Verifier) VerifyOrganization(ctx context.Context, ext *ExternalContext, backend ProtectedReader) (*Authority, error) {
	if v == nil || ext == nil || ext.hasState || ext.descriptor.Profile != ProfileOrganization {
		return nil, ErrExternalInvalid
	}
	if ext.provisioning.EvidenceClass != EvidenceProduction {
		return nil, ErrExternalInvalid
	}
	s, err := protectedSnapshot(ctx, backend)
	if err != nil {
		return nil, err
	}
	e, r, err := v.decode(Bundle{Envelope: s.Envelope, Receipt: s.Receipt, Transparency: s.Transparency})
	if err != nil {
		return nil, err
	}
	if err := ext.descriptor.scope(*e); err != nil {
		return nil, err
	}
	if err := v.threshold(ctx, e, descriptorAnchors(ext.descriptor), ext.descriptor.Threshold); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfRoot, err)
	}
	keys, err := v.loadKeys(ctx, e)
	if err != nil {
		return nil, err
	}
	if len(eligible(*e, keys)) < int(e.Threshold) {
		return nil, ErrRevoked
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, *r, s.Transparency)
	if err != nil {
		return nil, err
	}
	return ext.authority(*e, *r, c, eligible(*e, keys), ext.provisioning.EvidenceClass, s.BackendID, r.ReceiptDigest)
}

func descriptorAnchors(d DescriptorDocument) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(d.Anchors))
	for _, a := range d.Anchors {
		b, _ := base64.StdEncoding.Strict().DecodeString(a.PublicKeyBase64)
		out[a.Fingerprint] = ed25519.PublicKey(b)
	}
	return out
}

func (d DescriptorDocument) scope(e Envelope) error {
	if e.AuthorityID != d.AuthorityID {
		return ErrReceiptBinding
	}
	allowed := map[string]bool{}
	issuers := map[string]bool{}
	for _, o := range d.AllowedPolicyOrigins {
		allowed[o] = true
	}
	for _, s := range d.PublisherScopes {
		issuers[s.Issuer] = true
	}
	for _, o := range e.AllowedPolicyOrigins {
		if !allowed[o] {
			return ErrReceiptBinding
		}
	}
	for _, k := range e.RootKeys {
		if !issuers[k.Issuer] {
			return ErrReceiptBinding
		}
	}
	return nil
}

func compareState(s OSSAcceptedState, e Envelope, r Receipt) error {
	if e.Sequence < s.Sequence || e.RevocationEpoch < s.RevocationEpoch || r.TreeSize < s.TreeSize {
		return ErrRollback
	}
	if e.Sequence > s.Sequence {
		return ErrRefreshRequired
	}
	if e.AuthorityID != s.AuthorityID || e.PayloadSHA256 != s.EnvelopePayloadSHA256 || e.RevocationEpoch != s.RevocationEpoch || r.ReceiptDigest != s.ReceiptDigest || r.TreeSize != s.TreeSize || r.CheckpointDigest != s.CheckpointDigest {
		return ErrCheckpointMismatch
	}
	return nil
}

func (e *ExternalContext) authority(env Envelope, receipt Receipt, checkpoint Checkpoint, keys map[string]ed25519.PublicKey, class EvidenceClass, backend, protectedReceipt string) (*Authority, error) {
	scope := bootstrapDigest("tplaiter.dev/publisher-scope-set/v1", map[string]any{"publisherScopes": e.descriptor.PublisherScopes})
	selection := map[string]any{"kind": "organization"}
	if e.hasState {
		selection = map[string]any{"kind": "oss", "initialStateSHA256": e.initialStateSHA256}
	}
	config := bootstrapDigest("tplaiter.dev/bootstrap-effective-config/v1", map[string]any{"apiVersion": "tplaiter.dev/bootstrap-effective-config/v1", "profile": string(e.descriptor.Profile), "descriptorSHA256": e.descriptor.DescriptorSHA256, "provisioningSHA256": e.provisioning.ProvisioningSHA256, "publisherScopeSHA256": scope, "externalSelection": selection})
	external := map[string]any{"kind": "oss", "stateSHA256": e.state.StateSHA256}
	if !e.hasState {
		external = map[string]any{"kind": "organization", "backendId": backend, "protectedReceiptDigest": protectedReceipt}
	}
	auth := bootstrapDigest("tplaiter.dev/scoped-authority/v1", map[string]any{"apiVersion": "tplaiter.dev/scoped-authority/v1", "profile": string(e.descriptor.Profile), "descriptorSHA256": e.descriptor.DescriptorSHA256, "provisioningSHA256": e.provisioning.ProvisioningSHA256, "publisherScopeSHA256": scope, "authorityId": env.AuthorityID, "sequence": env.Sequence, "envelopePayloadSHA256": env.PayloadSHA256, "revocationEpoch": env.RevocationEpoch, "receiptDigest": receipt.ReceiptDigest, "treeSize": receipt.TreeSize, "checkpointDigest": receipt.CheckpointDigest, "externalState": external})
	assurance := PublisherVerified
	if e.descriptor.Profile == ProfileOrganization {
		assurance = OrganizationProtected
	}
	return &Authority{envelope: env, receipt: receipt, checkpoint: checkpoint, keys: keys, binding: ProfileBinding{ProfileBindingAPIVersion, e.descriptor.Profile, 1, config, env.PayloadSHA256, auth, assurance, class}, publisherScopes: append([]PublisherScope(nil), e.descriptor.PublisherScopes...)}, nil
}

type OSSRefreshProposal struct{ expected, next []byte }

func (p *OSSRefreshProposal) ExpectedStateSHA256() string {
	if p == nil {
		return ""
	}
	return string(p.expected)
}
func (p *OSSRefreshProposal) NextStateJSON() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.next...)
}

func (v *Verifier) PrepareOSSRefresh(ctx context.Context, ext *ExternalContext, current, next Bundle) (*OSSRefreshProposal, error) {
	old, err := v.VerifyOSS(ctx, ext, current)
	if err != nil {
		return nil, err
	}
	e, r, err := v.decode(next)
	if err != nil {
		return nil, err
	}
	if err := ext.descriptor.scope(*e); err != nil {
		return nil, err
	}
	if e.Sequence <= old.receipt.HighestAcceptedSequence || e.Rotation == nil || e.Rotation.PreviousSequence != old.receipt.HighestAcceptedSequence || r.PreviousReceiptDigest != old.receipt.ReceiptDigest || e.RevocationEpoch < old.receipt.RevocationEpoch || r.TreeSize < old.receipt.TreeSize {
		return nil, ErrRefreshRequired
	}
	keys, err := v.loadKeys(ctx, e)
	if err != nil {
		return nil, err
	}
	if v.clock.Now().UTC().After(mustTime(e.Rotation.OverlapUntil)) {
		if err := v.threshold(ctx, e, descriptorAnchors(ext.descriptor), ext.descriptor.Threshold); err != nil {
			return nil, err
		}
	} else if err := v.threshold(ctx, e, old.keys, old.envelope.Threshold); err != nil {
		return nil, err
	}
	if err := v.threshold(ctx, e, eligible(*e, keys), e.Threshold); err != nil {
		return nil, err
	}
	c, err := verifyTransparency(ctx, v.store, e.AuthorityID, e.PayloadSHA256, *r, next.Transparency)
	if err != nil {
		return nil, err
	}
	if err := v.verifyConsistency(ctx, old.checkpoint, c, next.Transparency.ConsistencyProofCAS); err != nil {
		return nil, err
	}
	state := OSSAcceptedState{APIVersion: OSSAcceptedStateAPIVersion, DescriptorSHA256: ext.descriptor.DescriptorSHA256, ProvisioningSHA256: ext.provisioning.ProvisioningSHA256, AuthorityID: e.AuthorityID, Sequence: e.Sequence, EnvelopePayloadSHA256: e.PayloadSHA256, RevocationEpoch: e.RevocationEpoch, ReceiptDigest: r.ReceiptDigest, TreeSize: r.TreeSize, CheckpointDigest: r.CheckpointDigest}
	state.StateSHA256 = state.ComputedSHA256()
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return &OSSRefreshProposal{expected: []byte(ext.state.StateSHA256), next: raw}, nil
}

func mustTime(raw string) (out time.Time) { out, _ = parseTime(raw); return }
