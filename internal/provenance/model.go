package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	RootTemplateLockAPIVersion = "tplaiter.dev/root-template-lock/v2"
	TemplateLockAPIVersion     = "tplaiter.dev/template-lock/v2"
	RootTemplateLockKind       = "RootTemplateLock"
	DependencyExportLockKind   = "DependencyExportLock"
)

var (
	errInvalidLock   = errors.New("provenance: invalid lock")
	ErrLegacyUnbound = errors.New(string(trustverify.TrustLegacyUnbound))
	digestRE         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitRE         = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	tokenRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
)

// RootTemplateLock is the sealed identity of one selected template root.
type RootTemplateLock struct {
	APIVersion     string                   `json:"apiVersion"`
	Kind           string                   `json:"kind"`
	TrustProfile   bootstrap.ProfileBinding `json:"trustProfile"`
	Policy         PolicyBinding            `json:"policy"`
	Root           RootSubject              `json:"root"`
	Renderer       RendererIdentity         `json:"renderer"`
	RootLockSHA256 string                   `json:"rootLockSHA256"`
}

type PolicyBinding struct {
	PolicySHA256 string `json:"policySHA256"`
}

type RootSubject struct {
	Origin            string `json:"origin"`
	TemplatePath      string `json:"templatePath"`
	RequestedRef      string `json:"requestedRef"`
	Commit            string `json:"commit"`
	TreeSHA256        string `json:"treeSHA256"`
	ContractSHA256    string `json:"contractSHA256"`
	StatementCAS      string `json:"statementCAS"`
	SignatureCAS      string `json:"signatureCAS"`
	KeyFingerprint    string `json:"keyFingerprint"`
	CheckpointCAS     string `json:"checkpointCAS"`
	InclusionProofCAS string `json:"inclusionProofCAS"`
}

type RendererIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TemplateLock is the dependency export lock. An empty, present dependencies
// array is the valid no-dependencies pair for a root lock.
type TemplateLock struct {
	APIVersion     string                   `json:"apiVersion"`
	Kind           string                   `json:"kind"`
	TrustProfile   bootstrap.ProfileBinding `json:"trustProfile"`
	RootLockSHA256 string                   `json:"rootLockSHA256"`
	Dependencies   []DependencySubject      `json:"dependencies"`
	LockSHA256     string                   `json:"lockSHA256"`
}

// DependencyExportLock is the descriptive name used by the wire kind.
type DependencyExportLock = TemplateLock

type DependencySubject struct {
	Origin            string `json:"origin"`
	TemplatePath      string `json:"templatePath"`
	RequestedRef      string `json:"requestedRef"`
	Commit            string `json:"commit"`
	TreeSHA256        string `json:"treeSHA256"`
	ContractSHA256    string `json:"contractSHA256"`
	StatementCAS      string `json:"statementCAS"`
	SignatureCAS      string `json:"signatureCAS"`
	KeyFingerprint    string `json:"keyFingerprint"`
	CheckpointCAS     string `json:"checkpointCAS"`
	InclusionProofCAS string `json:"inclusionProofCAS"`
}

func (s RootSubject) trustSubject() trustverify.Subject {
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}
func (s RootSubject) dependency() DependencySubject {
	return DependencySubject{s.Origin, s.TemplatePath, s.RequestedRef, s.Commit, s.TreeSHA256, s.ContractSHA256, s.StatementCAS, s.SignatureCAS, s.KeyFingerprint, s.CheckpointCAS, s.InclusionProofCAS}
}
func (s DependencySubject) trustSubject() trustverify.Subject {
	return trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func DecodeRootTemplateLock(raw []byte) (*RootTemplateLock, error) {
	if profilelessLegacyV1(raw, "tplater.dev/root-template-lock/v1", []string{"apiVersion", "kind", "policy", "root", "renderer", "rootLockSHA256"}, []string{"apiVersion", "kind", "policy", "root", "renderer", "rootLockSHA256"}) {
		return nil, ErrLegacyUnbound
	}
	if err := requireFields(raw, "apiVersion", "kind", "trustProfile", "policy", "root", "renderer", "rootLockSHA256"); err != nil {
		return nil, err
	}
	var v RootTemplateLock
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, err
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return &v, nil
}

func DecodeTemplateLock(raw []byte) (*TemplateLock, error) {
	if profilelessLegacyV1(raw, "tplater.dev/template-lock/v1", []string{"apiVersion", "kind", "rootLockSHA256", "dependencies", "lockSHA256"}, []string{"apiVersion", "kind", "rootLockSHA256", "dependencies", "lockSHA256"}) {
		return nil, ErrLegacyUnbound
	}
	if err := requireFields(raw, "apiVersion", "kind", "trustProfile", "rootLockSHA256", "dependencies", "lockSHA256"); err != nil {
		return nil, err
	}
	var v TemplateLock
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, err
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return &v, nil
}

func DecodeDependencyExportLock(raw []byte) (*DependencyExportLock, error) {
	return DecodeTemplateLock(raw)
}

func (v RootTemplateLock) Validate() error {
	if v.APIVersion != RootTemplateLockAPIVersion || v.Kind != RootTemplateLockKind || v.TrustProfile.Validate() != nil || !validDigest(v.Policy.PolicySHA256) || v.Policy.PolicySHA256 != v.TrustProfile.PolicySHA256 || !validRoot(v.Root) || !validRenderer(v.Renderer) || !validDigest(v.RootLockSHA256) {
		return errInvalidLock
	}
	got, err := ComputeRootLockSHA256(v)
	if err != nil || got != v.RootLockSHA256 {
		return errInvalidLock
	}
	return nil
}

func (v RootTemplateLock) ComputeSHA256() (string, error) { return ComputeRootLockSHA256(v) }
func (v TemplateLock) Validate() error {
	if v.APIVersion != TemplateLockAPIVersion || v.Kind != DependencyExportLockKind || v.TrustProfile.Validate() != nil || !validDigest(v.RootLockSHA256) || v.Dependencies == nil || len(v.Dependencies) > 4096 || !validDependencies(v.Dependencies) || !validDigest(v.LockSHA256) {
		return errInvalidLock
	}
	got, err := ComputeTemplateLockSHA256(v)
	if err != nil || got != v.LockSHA256 {
		return errInvalidLock
	}
	return nil
}

func (v TemplateLock) ComputeSHA256() (string, error) { return ComputeTemplateLockSHA256(v) }

// ValidateLockPair validates the root/dependency relationship without reading
// files, resolving references, or consulting authority.
func ValidateLockPair(root RootTemplateLock, dependencies TemplateLock) error {
	if err := root.Validate(); err != nil {
		return errInvalidLock
	}
	if err := dependencies.Validate(); err != nil {
		return errInvalidLock
	}
	if dependencies.RootLockSHA256 != root.RootLockSHA256 || !dependencies.TrustProfile.Equal(root.TrustProfile) {
		return fmt.Errorf("%w: root/profile binding mismatch", errInvalidLock)
	}
	return nil
}

func RootSubjectFromTrust(subject trustverify.Subject, evidence bootstrap.PublisherEvidence, checkpoint, inclusion string) RootSubject {
	return RootSubject{subject.Origin, subject.TemplatePath, subject.RequestedRef, subject.Commit, subject.TreeSHA256, subject.ContractSHA256, evidence.StatementCAS, evidence.SignatureCAS, evidence.KeyFingerprint, checkpoint, inclusion}
}
func (s RootSubject) Subject() trustverify.Subject { return s.trustSubject() }

// Validate applies the authoritative root-subject validation used by the
// sealed root lock. Consumers that retain the typed subject can reuse this
// boundary without duplicating provenance grammar.
func (s RootSubject) Validate() error {
	if !validRoot(s) {
		return errInvalidLock
	}
	return nil
}

func requireFields(raw []byte, names ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return errInvalidLock
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errInvalidLock
	}
	for _, n := range names {
		if _, ok := obj[n]; !ok {
			return fmt.Errorf("%w: missing %s", errInvalidLock, n)
		}
	}
	return nil
}

// profilelessLegacyV1 identifies only a closed, complete legacy v1 wire
// object with its required v2 trust-profile binding absent. Stable v2
// consumers classify that read-only input deterministically rather than
// classifying malformed or ambiguous raw JSON as legacy.
func profilelessLegacyV1(raw []byte, apiVersion string, required, allowed []string) bool {
	var obj map[string]json.RawMessage
	if canonicaljson.DecodeStrict(raw, &obj) != nil {
		return false
	}
	version, ok := obj["apiVersion"]
	if !ok || obj["trustProfile"] != nil {
		return false
	}
	var got string
	if json.Unmarshal(version, &got) != nil || got != apiVersion {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range obj {
		if _, ok := allowedSet[name]; !ok {
			return false
		}
	}
	for _, name := range required {
		if value, ok := obj[name]; !ok || string(value) == "null" {
			return false
		}
	}
	return true
}
func validDigest(s string) bool { return digestRE.MatchString(s) }
func validRoot(s RootSubject) bool {
	return tokenRE.MatchString(s.Origin) && safePath(s.TemplatePath) && tokenRE.MatchString(s.RequestedRef) && commitRE.MatchString(s.Commit) && validDigest(s.TreeSHA256) && validDigest(s.ContractSHA256) && validDigest(s.StatementCAS) && validDigest(s.SignatureCAS) && validDigest(s.KeyFingerprint) && validDigest(s.CheckpointCAS) && validDigest(s.InclusionProofCAS)
}
func validDependencies(xs []DependencySubject) bool {
	for _, s := range xs {
		if !tokenRE.MatchString(s.Origin) || !safePath(s.TemplatePath) || !tokenRE.MatchString(s.RequestedRef) || !commitRE.MatchString(s.Commit) || !validDigest(s.TreeSHA256) || !validDigest(s.ContractSHA256) || !validDigest(s.StatementCAS) || !validDigest(s.SignatureCAS) || !validDigest(s.KeyFingerprint) || !validDigest(s.CheckpointCAS) || !validDigest(s.InclusionProofCAS) {
			return false
		}
	}
	return true
}
func validRenderer(r RendererIdentity) bool {
	return tokenRE.MatchString(r.Name) && tokenRE.MatchString(r.Version)
}
func safePath(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
