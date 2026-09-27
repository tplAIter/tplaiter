// Package bootstrap verifies externally anchored, public trust metadata. It has no network or system-store implementation.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	TrustRootsAPIVersion   = "tplaiter.dev/trust-roots/v1"
	TrustReceiptAPIVersion = "tplaiter.dev/trust-receipt/v1"
	CheckpointAPIVersion   = "tplaiter.dev/transparency-checkpoint/v1"
	InclusionAPIVersion    = "tplaiter.dev/transparency-inclusion/v1"
	ConsistencyAPIVersion  = "tplaiter.dev/transparency-consistency/v1"
	maxSafeInteger         = uint64(1<<53 - 1)
)

type Envelope struct {
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
	PayloadSHA256        string       `json:"payloadSHA256"`
	Signatures           []Signature  `json:"signatures"`
}
type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}
type RootKey struct {
	Fingerprint  string `json:"fingerprint"`
	PublicKeyCAS string `json:"publicKeyCAS"`
	Issuer       string `json:"issuer"`
	Status       string `json:"status"`
}
type Revocation struct {
	Fingerprint       string `json:"fingerprint"`
	EffectiveSequence uint64 `json:"effectiveSequence"`
}
type Rotation struct {
	PreviousSequence uint64 `json:"previousSequence"`
	OverlapUntil     string `json:"overlapUntil"`
}
type Signature struct {
	KeyFingerprint string `json:"keyFingerprint"`
	SignatureCAS   string `json:"signatureCAS"`
}
type Receipt struct {
	APIVersion              string `json:"apiVersion"`
	AuthorityID             string `json:"authorityId"`
	HighestAcceptedSequence uint64 `json:"highestAcceptedSequence"`
	EnvelopePayloadSHA256   string `json:"envelopePayloadSHA256"`
	RevocationEpoch         uint64 `json:"revocationEpoch"`
	TreeSize                uint64 `json:"treeSize"`
	CheckpointDigest        string `json:"checkpointDigest"`
	PreviousReceiptDigest   string `json:"previousReceiptDigest"`
	ReceiptDigest           string `json:"receiptDigest"`
}
type Checkpoint struct {
	APIVersion  string `json:"apiVersion"`
	AuthorityID string `json:"authorityId"`
	TreeSize    uint64 `json:"treeSize"`
	RootHash    string `json:"rootHash"`
}
type InclusionProof struct {
	APIVersion string   `json:"apiVersion"`
	LeafIndex  uint64   `json:"leafIndex"`
	TreeSize   uint64   `json:"treeSize"`
	Hashes     []string `json:"hashes"`
}
type ConsistencyProof struct {
	APIVersion  string   `json:"apiVersion"`
	OldTreeSize uint64   `json:"oldTreeSize"`
	NewTreeSize uint64   `json:"newTreeSize"`
	Hashes      []string `json:"hashes"`
}

func DecodeEnvelope(raw []byte) (*Envelope, error) {
	return decodeEnvelope(raw, true)
}

// decodeDevelopmentEnvelope retains the complete envelope wire and semantic
// validation contract while allowing the explicitly unsigned development
// form. Stable callers must use DecodeEnvelope, which still requires signing
// evidence.
func decodeDevelopmentEnvelope(raw []byte) (*Envelope, error) {
	return decodeEnvelope(raw, false)
}

func decodeEnvelope(raw []byte, requireSignatures bool) (*Envelope, error) {
	if err := requireEnvelopeFields(raw); err != nil {
		return nil, err
	}
	var e Envelope
	if err := canonicaljson.DecodeStrict(raw, &e); err != nil {
		return nil, fmt.Errorf("bootstrap: decode envelope: %w", err)
	}
	if err := e.validate(requireSignatures); err != nil {
		return nil, err
	}
	return &e, nil
}
func DecodeReceipt(raw []byte) (*Receipt, error) {
	if err := requireFields(raw, receiptFields); err != nil {
		return nil, err
	}
	var r Receipt
	if err := canonicaljson.DecodeStrict(raw, &r); err != nil {
		return nil, fmt.Errorf("bootstrap: decode receipt: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

var (
	envelopeFields    = []string{"apiVersion", "authorityId", "sequence", "validity", "allowedPolicyOrigins", "rootKeys", "threshold", "revocationEpoch", "revocations", "payloadSHA256", "signatures"}
	receiptFields     = []string{"apiVersion", "authorityId", "highestAcceptedSequence", "envelopePayloadSHA256", "revocationEpoch", "treeSize", "checkpointDigest", "previousReceiptDigest", "receiptDigest"}
	checkpointFields  = []string{"apiVersion", "authorityId", "treeSize", "rootHash"}
	inclusionFields   = []string{"apiVersion", "leafIndex", "treeSize", "hashes"}
	consistencyFields = []string{"apiVersion", "oldTreeSize", "newTreeSize", "hashes"}
)

// DecodeCheckpoint and proof decoders retain required-field presence for zero
// counters. Callers that consume these wire records should use these entry points.
func DecodeCheckpoint(raw []byte) (*Checkpoint, error) {
	var v Checkpoint
	if err := requireFields(raw, checkpointFields); err != nil {
		return nil, err
	}
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, fmt.Errorf("bootstrap: decode checkpoint: %w", err)
	}
	if v.APIVersion != CheckpointAPIVersion || !validToken(v.AuthorityID) || v.TreeSize == 0 || v.TreeSize > maxSafeInteger || !validDigest(v.RootHash) {
		return nil, errors.New("bootstrap: invalid checkpoint")
	}
	return &v, nil
}
func DecodeInclusionProof(raw []byte) (*InclusionProof, error) {
	var v InclusionProof
	if err := requireFields(raw, inclusionFields); err != nil {
		return nil, err
	}
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, fmt.Errorf("bootstrap: decode inclusion proof: %w", err)
	}
	if v.APIVersion != InclusionAPIVersion || v.TreeSize == 0 || v.TreeSize > maxSafeInteger || v.LeafIndex >= v.TreeSize || v.Hashes == nil {
		return nil, errors.New("bootstrap: invalid inclusion proof")
	}
	return &v, nil
}
func DecodeConsistencyProof(raw []byte) (*ConsistencyProof, error) {
	var v ConsistencyProof
	if err := requireFields(raw, consistencyFields); err != nil {
		return nil, err
	}
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, fmt.Errorf("bootstrap: decode consistency proof: %w", err)
	}
	if v.APIVersion != ConsistencyAPIVersion || v.OldTreeSize == 0 || v.NewTreeSize < v.OldTreeSize || v.NewTreeSize > maxSafeInteger || v.Hashes == nil {
		return nil, errors.New("bootstrap: invalid consistency proof")
	}
	return &v, nil
}

func requireEnvelopeFields(raw []byte) error {
	top, err := rawObject(raw, envelopeFields)
	if err != nil {
		return err
	}
	if err = requireFields(top["validity"], []string{"notBefore", "notAfter"}); err != nil {
		return err
	}
	for _, spec := range []struct {
		key    string
		fields []string
	}{{"rootKeys", []string{"fingerprint", "publicKeyCAS", "issuer", "status"}}, {"revocations", []string{"fingerprint", "effectiveSequence"}}, {"signatures", []string{"keyFingerprint", "signatureCAS"}}} {
		items, err := rawArray(top[spec.key])
		if err != nil {
			return err
		}
		for _, item := range items {
			if err := requireFields(item, spec.fields); err != nil {
				return err
			}
		}
	}
	if rotation, ok := top["rotation"]; ok {
		if err := requireFields(rotation, []string{"previousSequence", "overlapUntil"}); err != nil {
			return err
		}
	}
	return nil
}

func requireFields(raw []byte, fields []string) error { _, err := rawObject(raw, fields); return err }
func rawObject(raw []byte, fields []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var v map[string]json.RawMessage
	if err := dec.Decode(&v); err != nil || v == nil {
		return nil, errors.New("bootstrap: expected object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("bootstrap: trailing JSON value")
	}
	for _, f := range fields {
		if _, ok := v[f]; !ok {
			return nil, fmt.Errorf("bootstrap: missing required field %q", f)
		}
	}
	return v, nil
}
func rawArray(raw []byte) ([]json.RawMessage, error) {
	var v []json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return nil, errors.New("bootstrap: expected array")
	}
	return v, nil
}
func (e Envelope) Validate() error {
	return e.validate(true)
}

func (e Envelope) validate(requireSignatures bool) error {
	if e.APIVersion != TrustRootsAPIVersion || !validToken(e.AuthorityID) || e.Sequence == 0 || e.Sequence > maxSafeInteger || e.RevocationEpoch > maxSafeInteger {
		return errors.New("bootstrap: invalid envelope identity")
	}
	if _, _, err := e.Validity.bounds(); err != nil {
		return err
	}
	if len(e.AllowedPolicyOrigins) == 0 || !sortedUnique(e.AllowedPolicyOrigins) {
		return errors.New("bootstrap: invalid policy origins")
	}
	for _, x := range e.AllowedPolicyOrigins {
		if !strings.HasPrefix(x, "https://") || strings.ContainsAny(x, "\x00\r\n") {
			return errors.New("bootstrap: invalid policy origin")
		}
	}
	if len(e.RootKeys) == 0 || (requireSignatures && len(e.Signatures) == 0) || !validDigest(e.PayloadSHA256) || e.Threshold == 0 || int(e.Threshold) > len(e.RootKeys) {
		return errors.New("bootstrap: invalid envelope trust material")
	}
	seen := map[string]bool{}
	for _, k := range e.RootKeys {
		if !validFingerprint(k.Fingerprint) || !validDigest(k.PublicKeyCAS) || !validToken(k.Issuer) || (k.Status != "active" && k.Status != "retiring") || seen[k.Fingerprint] {
			return errors.New("bootstrap: invalid root key")
		}
		seen[k.Fingerprint] = true
	}
	if !sort.SliceIsSorted(e.RootKeys, func(i, j int) bool { return e.RootKeys[i].Fingerprint < e.RootKeys[j].Fingerprint }) {
		return errors.New("bootstrap: root keys unsorted")
	}
	seen = map[string]bool{}
	for _, s := range e.Signatures {
		if !validFingerprint(s.KeyFingerprint) || !validDigest(s.SignatureCAS) || seen[s.KeyFingerprint] {
			return errors.New("bootstrap: invalid signature")
		}
		seen[s.KeyFingerprint] = true
	}
	if !sort.SliceIsSorted(e.Signatures, func(i, j int) bool { return e.Signatures[i].KeyFingerprint < e.Signatures[j].KeyFingerprint }) {
		return errors.New("bootstrap: signatures unsorted")
	}
	seen = map[string]bool{}
	for _, r := range e.Revocations {
		if !validFingerprint(r.Fingerprint) || r.EffectiveSequence == 0 || r.EffectiveSequence > maxSafeInteger || seen[r.Fingerprint] {
			return errors.New("bootstrap: invalid revocation")
		}
		seen[r.Fingerprint] = true
	}
	if e.Revocations == nil || !sort.SliceIsSorted(e.Revocations, func(i, j int) bool { return e.Revocations[i].Fingerprint < e.Revocations[j].Fingerprint }) {
		return errors.New("bootstrap: revocations unsorted")
	}
	if e.Rotation != nil {
		if e.Rotation.PreviousSequence == 0 || e.Rotation.PreviousSequence >= e.Sequence {
			return errors.New("bootstrap: invalid rotation")
		}
		if _, err := parseTime(e.Rotation.OverlapUntil); err != nil {
			return err
		}
	}
	return nil
}
func (r Receipt) Validate() error {
	if r.APIVersion != TrustReceiptAPIVersion || !validToken(r.AuthorityID) || r.HighestAcceptedSequence == 0 || r.TreeSize == 0 || r.HighestAcceptedSequence > maxSafeInteger || r.TreeSize > maxSafeInteger || r.RevocationEpoch > maxSafeInteger {
		return errors.New("bootstrap: invalid receipt")
	}
	for _, d := range []string{r.EnvelopePayloadSHA256, r.CheckpointDigest, r.ReceiptDigest} {
		if !validDigest(d) {
			return errors.New("bootstrap: invalid receipt digest")
		}
	}
	if r.PreviousReceiptDigest != "" && !validDigest(r.PreviousReceiptDigest) {
		return errors.New("bootstrap: invalid previous receipt digest")
	}
	return nil
}
func (v Validity) bounds() (time.Time, time.Time, error) {
	a, e := parseTime(v.NotBefore)
	if e != nil {
		return time.Time{}, time.Time{}, e
	}
	b, e := parseTime(v.NotAfter)
	if e != nil || !a.Before(b) {
		return time.Time{}, time.Time{}, errors.New("bootstrap: invalid validity interval")
	}
	return a, b, nil
}
func parseTime(s string) (time.Time, error) {
	v, e := time.Parse(time.RFC3339, s)
	if e != nil || !strings.HasSuffix(s, "Z") || v.Format(time.RFC3339) != s {
		return time.Time{}, errors.New("bootstrap: timestamp must be canonical UTC RFC3339")
	}
	return v, nil
}
func DecodePublicKey(v []byte) (ed25519.PublicKey, error) {
	if strings.ContainsAny(string(v), "= \t\r\n") {
		return nil, errors.New("bootstrap: invalid public key encoding")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(string(v))
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bootstrap: invalid public key")
	}
	return ed25519.PublicKey(b), nil
}
func DecodeSignature(v []byte) ([]byte, error) {
	if strings.ContainsAny(string(v), "= \t\r\n") {
		return nil, errors.New("bootstrap: invalid signature encoding")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(string(v))
	if e != nil || len(b) != ed25519.SignatureSize {
		return nil, errors.New("bootstrap: invalid signature")
	}
	return b, nil
}
func EncodePublicKey(k ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(k) }
func EncodeSignature(s []byte) string            { return base64.RawURLEncoding.EncodeToString(s) }
func Fingerprint(k ed25519.PublicKey) string {
	s := sha256.Sum256(k)
	return "sha256:" + hex.EncodeToString(s[:])
}
func validFingerprint(s string) bool { return validDigest(s) }
func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s[7:]) != s[7:] {
		return false
	}
	_, e := hex.DecodeString(s[7:])
	return e == nil
}
func validToken(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n\t ")
}
func sortedUnique(x []string) bool {
	for i := 1; i < len(x); i++ {
		if x[i-1] >= x[i] {
			return false
		}
	}
	return true
}
