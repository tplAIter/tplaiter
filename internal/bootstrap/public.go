package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"regexp"
)

const PublisherStatementAPIVersion = "tplaiter.dev/publisher-statement/v1"

type SubjectIdentity struct {
	Origin         string `json:"origin"`
	TemplatePath   string `json:"templatePath"`
	Commit         string `json:"commit"`
	TreeSHA256     string `json:"treeSHA256"`
	ContractSHA256 string `json:"contractSHA256"`
}
type PublisherExpectation struct {
	PolicyOrigin, Issuer, Predicate, Usage string
	Subject                                SubjectIdentity
}
type PublisherEvidence struct{ StatementCAS, SignatureCAS, KeyFingerprint string }
type PublisherStatement struct {
	APIVersion   string          `json:"apiVersion"`
	PolicyOrigin string          `json:"policyOrigin"`
	Issuer       string          `json:"issuer"`
	Predicate    string          `json:"predicate"`
	Usage        string          `json:"usage"`
	Subject      SubjectIdentity `json:"subject"`
}
type VerifiedPublisherClaim struct {
	expected  PublisherExpectation
	authority string
}

func (c *VerifiedPublisherClaim) Expectation() PublisherExpectation {
	if c == nil {
		return PublisherExpectation{}
	}
	return c.expected
}
func (c *VerifiedPublisherClaim) AuthoritySHA256() string {
	if c == nil {
		return ""
	}
	return c.authority
}
func DecodePublisherStatement(raw []byte) (*PublisherStatement, error) {
	if _, e := rawObject(raw, []string{"apiVersion", "policyOrigin", "issuer", "predicate", "usage", "subject"}); e != nil {
		return nil, e
	}
	var s PublisherStatement
	if e := canonicaljson.DecodeStrict(raw, &s); e != nil {
		return nil, e
	}
	if !validStatement(s) {
		return nil, errors.New("bootstrap: invalid publisher statement")
	}
	return &s, nil
}
func validStatement(s PublisherStatement) bool {
	return s.APIVersion == PublisherStatementAPIVersion && validOrigin(s.PolicyOrigin) && validDescriptorToken(s.Issuer, 256) && validOrigin(s.Predicate) && s.Usage == "template-source" && validOrigin(s.Subject.Origin) && validPathIdentity(s.Subject.TemplatePath) && regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`).MatchString(s.Subject.Commit) && validDigest(s.Subject.TreeSHA256) && validDigest(s.Subject.ContractSHA256)
}
func (v *Verifier) VerifyPublisherClaim(ctx context.Context, a *Authority, x PublisherExpectation, r PublisherEvidence) (*VerifiedPublisherClaim, error) {
	if v == nil || ctx == nil || a == nil || !validStatement(PublisherStatement{PublisherStatementAPIVersion, x.PolicyOrigin, x.Issuer, x.Predicate, x.Usage, x.Subject}) {
		return nil, errors.New("bootstrap: publisher authority required")
	}
	lo, hi, _ := a.envelope.Validity.bounds()
	if n := v.clock.Now().UTC(); n.Before(lo) || !n.Before(hi) {
		return nil, ErrExpired
	}
	key, ok := a.keys[r.KeyFingerprint]
	if !ok || revoked(a.envelope, r.KeyFingerprint) {
		return nil, ErrRevoked
	}
	raw, e := readEvidence(ctx, v.store, r.StatementCAS)
	if e != nil {
		return nil, e
	}
	s, e := DecodePublisherStatement(raw)
	if e != nil {
		return nil, e
	}
	if s.PolicyOrigin != x.PolicyOrigin || s.Issuer != x.Issuer || s.Predicate != x.Predicate || s.Usage != x.Usage || s.Subject != x.Subject || !a.AllowsPolicyOrigin(s.PolicyOrigin) {
		return nil, errors.New("bootstrap: publisher scope denied")
	}
	found := false
	for _, q := range a.publisherScopes {
		if q.PolicyOrigin == s.PolicyOrigin && q.Issuer == s.Issuer && q.SourceOrigin == s.Subject.Origin && q.TemplatePath == s.Subject.TemplatePath && q.Predicate == s.Predicate && q.Usage == s.Usage {
			found = true
		}
	}
	if !found {
		return nil, errors.New("bootstrap: publisher scope denied")
	}
	issuer := ""
	for _, k := range a.envelope.RootKeys {
		if k.Fingerprint == r.KeyFingerprint {
			issuer = k.Issuer
		}
	}
	if issuer != s.Issuer {
		return nil, errors.New("bootstrap: publisher issuer mismatch")
	}
	sigraw, e := readEvidence(ctx, v.store, r.SignatureCAS)
	if e != nil {
		return nil, e
	}
	sig, e := DecodeSignature(sigraw)
	if e != nil {
		return nil, e
	}
	d, e := DomainDigest(PublisherStatementAPIVersion, *s)
	if e != nil {
		return nil, e
	}
	msg, e := rawDigest(d)
	if e != nil {
		return nil, e
	}
	if !ed25519.Verify(key, msg, sig) {
		return nil, fmt.Errorf("bootstrap: invalid publisher signature")
	}
	return &VerifiedPublisherClaim{x, a.binding.AuthoritySHA256}, nil
}
func VerifyArtifactTransparency(ctx context.Context, a *Authority, store interface {
	Read(context.Context, string) ([]byte, error)
}, leaf string, refs TransparencyEvidence) error {
	if a == nil || leaf == "" {
		return errors.New("bootstrap: stable authority and leaf required")
	}
	_, e := verifyTransparency(ctx, store, a.receipt.AuthorityID, leaf, a.receipt, refs)
	return e
}
