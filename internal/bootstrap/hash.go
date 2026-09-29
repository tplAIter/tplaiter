package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func DomainDigest(subject string, value any) (string, error) {
	b, e := canonicaljson.Canonical(value)
	if e != nil {
		return "", fmt.Errorf("bootstrap: canonicalize: %w", e)
	}
	h := sha256.New()
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func bootstrapDigest(version string, payload any) string {
	d, _ := DomainDigest(version, payload)
	return d
}

func (e Envelope) ComputePayloadSHA256() (string, error) {
	return DomainDigest(TrustRootsAPIVersion, struct {
		APIVersion           string       `json:"apiVersion"`
		AuthorityID          string       `json:"authorityId"`
		Sequence             uint64       `json:"sequence"`
		Validity             Validity     `json:"validity"`
		AllowedPolicyOrigins []string     `json:"allowedPolicyOrigins"`
		RootKeys             []RootKey    `json:"rootKeys"`
		Threshold            uint32       `json:"threshold"`
		RevocationEpoch      uint64       `json:"revocationEpoch"`
		Revocations          []Revocation `json:"revocations"`
		Rotation             *Rotation    `json:"rotation,omitempty"`
	}{e.APIVersion, e.AuthorityID, e.Sequence, e.Validity, e.AllowedPolicyOrigins, e.RootKeys, e.Threshold, e.RevocationEpoch, e.Revocations, e.Rotation})
}

func (e Envelope) VerifyPayloadSHA256() error {
	d, x := e.ComputePayloadSHA256()
	if x != nil {
		return x
	}
	if d != e.PayloadSHA256 {
		return fmt.Errorf("bootstrap: envelope payload digest mismatch")
	}
	return nil
}

func (r Receipt) ComputeDigest() (string, error) {
	return DomainDigest(TrustReceiptAPIVersion, struct {
		APIVersion              string `json:"apiVersion"`
		AuthorityID             string `json:"authorityId"`
		HighestAcceptedSequence uint64 `json:"highestAcceptedSequence"`
		EnvelopePayloadSHA256   string `json:"envelopePayloadSHA256"`
		RevocationEpoch         uint64 `json:"revocationEpoch"`
		TreeSize                uint64 `json:"treeSize"`
		CheckpointDigest        string `json:"checkpointDigest"`
		PreviousReceiptDigest   string `json:"previousReceiptDigest"`
	}{r.APIVersion, r.AuthorityID, r.HighestAcceptedSequence, r.EnvelopePayloadSHA256, r.RevocationEpoch, r.TreeSize, r.CheckpointDigest, r.PreviousReceiptDigest})
}

func (r Receipt) VerifyDigest() error {
	d, e := r.ComputeDigest()
	if e != nil {
		return e
	}
	if d != r.ReceiptDigest {
		return fmt.Errorf("bootstrap: receipt digest mismatch")
	}
	return nil
}

func rawDigest(v string) ([]byte, error) {
	if !validDigest(v) {
		return nil, fmt.Errorf("bootstrap: invalid digest")
	}
	return hex.DecodeString(v[7:])
}
