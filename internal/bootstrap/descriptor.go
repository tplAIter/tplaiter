package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const (
	DescriptorAPIVersion   = "tplaiter.dev/bootstrap-descriptor/v1"
	ProvisioningAPIVersion = "tplaiter.dev/bootstrap-provisioning/v1"
	maxBootstrapDocument   = 1 << 20
)

type DescriptorDocument struct {
	APIVersion           string             `json:"apiVersion"`
	Profile              ProfileID          `json:"profile"`
	AuthorityID          string             `json:"authorityId"`
	Anchors              []DescriptorAnchor `json:"anchors"`
	Threshold            uint32             `json:"threshold"`
	AllowedPolicyOrigins []string           `json:"allowedPolicyOrigins"`
	PublisherScopes      []PublisherScope   `json:"publisherScopes"`
	DescriptorSHA256     string             `json:"descriptorSHA256"`
}
type DescriptorAnchor struct {
	Fingerprint     string `json:"fingerprint"`
	PublicKeyBase64 string `json:"publicKeyBase64"`
}
type PublisherScope struct {
	PolicyOrigin string `json:"policyOrigin"`
	Issuer       string `json:"issuer"`
	SourceOrigin string `json:"sourceOrigin"`
	TemplatePath string `json:"templatePath"`
	Predicate    string `json:"predicate"`
	Usage        string `json:"usage"`
}
type ProvisioningRecord struct {
	APIVersion                   string        `json:"apiVersion"`
	Mode                         string        `json:"mode"`
	DescriptorSHA256             string        `json:"descriptorSHA256"`
	AuthenticationEvidenceSHA256 string        `json:"authenticationEvidenceSHA256"`
	EvidenceClass                EvidenceClass `json:"evidenceClass"`
	ProvisioningSHA256           string        `json:"provisioningSHA256"`
}

var (
	descriptorFields   = []string{"apiVersion", "profile", "authorityId", "anchors", "threshold", "allowedPolicyOrigins", "publisherScopes", "descriptorSHA256"}
	provisioningFields = []string{"apiVersion", "mode", "descriptorSHA256", "authenticationEvidenceSHA256", "evidenceClass", "provisioningSHA256"}
)

func DecodeDescriptorDocument(raw []byte) (*DescriptorDocument, error) {
	if len(raw) > maxBootstrapDocument {
		return nil, errors.New("bootstrap: descriptor exceeds size limit")
	}
	var d DescriptorDocument
	if err := decodeBootstrapDocument(raw, descriptorFields, &d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.DescriptorSHA256 != d.ComputedSHA256() {
		return nil, errors.New("bootstrap: descriptor digest mismatch")
	}
	return &d, nil
}

func DecodeProvisioningRecord(raw []byte) (*ProvisioningRecord, error) {
	if len(raw) > maxBootstrapDocument {
		return nil, errors.New("bootstrap: provisioning exceeds size limit")
	}
	var p ProvisioningRecord
	if err := decodeBootstrapDocument(raw, provisioningFields, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.ProvisioningSHA256 != p.ComputedSHA256() {
		return nil, errors.New("bootstrap: provisioning digest mismatch")
	}
	return &p, nil
}

func decodeBootstrapDocument(raw []byte, fields []string, dst any) error {
	if !utf8.Valid(raw) {
		return errors.New("bootstrap: invalid UTF-8")
	}
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return errors.New("bootstrap: document must be object")
	}
	for _, f := range fields {
		if _, ok := object[f]; !ok {
			return fmt.Errorf("bootstrap: missing required field %q", f)
		}
	}
	if err := canonicaljson.DecodeStrict(raw, dst); err != nil {
		return fmt.Errorf("bootstrap: strict document decode: %w", err)
	}
	return nil
}

func (d DescriptorDocument) Validate() error {
	if d.APIVersion != DescriptorAPIVersion || (d.Profile != ProfileOSS && d.Profile != ProfileOrganization) || !validDescriptorToken(d.AuthorityID, 256) || len(d.Anchors) == 0 || len(d.Anchors) > 64 || d.Threshold == 0 || d.Threshold > uint32(len(d.Anchors)) || len(d.AllowedPolicyOrigins) == 0 || len(d.AllowedPolicyOrigins) > 256 || len(d.PublisherScopes) == 0 || len(d.PublisherScopes) > 1024 || !validDigest(d.DescriptorSHA256) { //nolint:gosec // len(d.Anchors) is bounded to 64 earlier in the same condition
		return errors.New("bootstrap: invalid descriptor")
	}
	for i, a := range d.Anchors {
		if !validAnchor(a) || (i > 0 && d.Anchors[i-1].Fingerprint >= a.Fingerprint) {
			return errors.New("bootstrap: invalid anchor ordering")
		}
	}
	allowed := map[string]bool{}
	for i, origin := range d.AllowedPolicyOrigins {
		if !validOrigin(origin) || (i > 0 && d.AllowedPolicyOrigins[i-1] >= origin) || allowed[origin] {
			return errors.New("bootstrap: invalid policy origins")
		}
		allowed[origin] = true
	}
	seen := map[string]bool{}
	for i, s := range d.PublisherScopes {
		if !s.valid(allowed) || seen[s.tuple()] || (i > 0 && d.PublisherScopes[i-1].tuple() >= s.tuple()) {
			return errors.New("bootstrap: invalid publisher scopes")
		}
		seen[s.tuple()] = true
	}
	return nil
}

func validAnchor(a DescriptorAnchor) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(a.PublicKeyBase64)
	return err == nil && len(b) == 32 && a.Fingerprint == Fingerprint(b)
}

func (s PublisherScope) valid(allowed map[string]bool) bool {
	return allowed[s.PolicyOrigin] && validOrigin(s.PolicyOrigin) && validDescriptorToken(s.Issuer, 256) && validOrigin(s.SourceOrigin) && validPathIdentity(s.TemplatePath) && validOrigin(s.Predicate) && s.Usage == "template-source"
}

func (s PublisherScope) tuple() string {
	return strings.Join([]string{s.PolicyOrigin, s.Issuer, s.SourceOrigin, s.TemplatePath, s.Predicate, s.Usage}, "\x00")
}

func validDescriptorToken(s string, limit int) bool { //nolint:unparam // explicit bound keeps each token limit visible at the call site
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validPathIdentity(s string) bool {
	if s == "." {
		return true
	}
	if s == "" || len([]rune(s)) > 1024 || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.ContainsAny(s, `\\:`) || !utf8.ValidString(s) {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, r := range p {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}

func validOrigin(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 2048 || strings.ContainsAny(s, "\\ \t\r\n\x00") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Scheme != strings.ToLower(u.Scheme) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || u.Host != strings.ToLower(u.Host) {
		return false
	}
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' {
			if strings.ToUpper(s[i+1:i+3]) != s[i+1:i+3] {
				return false
			}
			switch strings.ToLower(s[i+1 : i+3]) {
			case "2f", "5c", "2e":
				return false
			}
		}
	}
	if strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/./") || strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/.") || strings.HasSuffix(u.Path, "/..") {
		return false
	}
	return true
}

func (d DescriptorDocument) ComputedSHA256() string { return descriptorDigest(d) }
func (p ProvisioningRecord) Validate() error {
	if p.APIVersion != ProvisioningAPIVersion || (p.Mode != "release-distribution" && p.Mode != "operator-pinned") || !validDigest(p.DescriptorSHA256) || !validDigest(p.AuthenticationEvidenceSHA256) || p.EvidenceClass != EvidenceProduction && p.EvidenceClass != EvidenceSimulated || !validDigest(p.ProvisioningSHA256) {
		return errors.New("bootstrap: invalid provisioning record")
	}
	return nil
}
func (p ProvisioningRecord) ComputedSHA256() string { return provisioningDigest(p) }

func descriptorDigest(d DescriptorDocument) string {
	return bootstrapDigest(DescriptorAPIVersion, struct {
		APIVersion  string             `json:"apiVersion"`
		Profile     ProfileID          `json:"profile"`
		AuthorityID string             `json:"authorityId"`
		Anchors     []DescriptorAnchor `json:"anchors"`
		Threshold   uint32             `json:"threshold"`
		Allowed     []string           `json:"allowedPolicyOrigins"`
		Scopes      []PublisherScope   `json:"publisherScopes"`
	}{d.APIVersion, d.Profile, d.AuthorityID, d.Anchors, d.Threshold, d.AllowedPolicyOrigins, d.PublisherScopes})
}

func provisioningDigest(p ProvisioningRecord) string {
	return bootstrapDigest(ProvisioningAPIVersion, struct {
		APIVersion string        `json:"apiVersion"`
		Mode       string        `json:"mode"`
		Descriptor string        `json:"descriptorSHA256"`
		Evidence   string        `json:"authenticationEvidenceSHA256"`
		Class      EvidenceClass `json:"evidenceClass"`
	}{p.APIVersion, p.Mode, p.DescriptorSHA256, p.AuthenticationEvidenceSHA256, p.EvidenceClass})
}
