package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

func testDescriptor(t *testing.T) DescriptorDocument {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	a := DescriptorAnchor{Fingerprint(key.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	d := DescriptorDocument{APIVersion: DescriptorAPIVersion, Profile: ProfileOSS, AuthorityID: "synthetic-authority", Anchors: []DescriptorAnchor{a}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: "https://example.test/source", TemplatePath: "templates/base", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	d.DescriptorSHA256 = d.ComputedSHA256()
	return d
}

func TestDescriptorRoundTripAndSelfHash(t *testing.T) {
	d := testDescriptor(t)
	if got := d.ComputedSHA256(); got != "sha256:5d4c1dfb3b9bf47a0ffc44eff8f943ca6a5916b0cdf256a645ebca4ac7491676" {
		t.Fatalf("descriptor vector = %s", got)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDescriptorDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ComputedSHA256() != got.DescriptorSHA256 {
		t.Fatal("descriptor self hash changed")
	}
	var unknown map[string]any
	if err := json.Unmarshal(raw, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["unexpected"] = true
	raw, _ = json.Marshal(unknown)
	if _, err := DecodeDescriptorDocument(raw); err == nil {
		t.Fatal("unknown descriptor field accepted")
	}
}

func TestDescriptorRejectsScopeAndAnchorViolations(t *testing.T) {
	d := testDescriptor(t)
	d.PublisherScopes[0].SourceOrigin = "https://example.test/other"
	d.DescriptorSHA256 = d.ComputedSHA256()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.PublisherScopes[0].PolicyOrigin = "https://other.test/policy"
	if err := d.Validate(); err == nil {
		t.Fatal("scope origin outside allowlist accepted")
	}
	d = testDescriptor(t)
	d.Anchors[0].Fingerprint = strings.Repeat("0", 71)
	if err := d.Validate(); err == nil {
		t.Fatal("fingerprint mismatch accepted")
	}
	if _, err := DecodeDescriptorDocument([]byte(`{"apiVersion":"tplaiter.dev/bootstrap-descriptor/v1","profile":"oss","authorityId":"x","anchors":[],"threshold":0,"allowedPolicyOrigins":[],"publisherScopes":[],"descriptorSHA256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`)); err == nil {
		t.Fatal("empty descriptor accepted")
	}
}

func TestProvisioningRecordValidation(t *testing.T) {
	p := ProvisioningRecord{APIVersion: ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: testDescriptor(t).DescriptorSHA256, AuthenticationEvidenceSHA256: digest(), EvidenceClass: EvidenceSimulated}
	p.ProvisioningSHA256 = p.ComputedSHA256()
	if p.ProvisioningSHA256 != "sha256:06b6472ecb2ea44c97bf32405a85444b9f21bb4329bcdcf2448377e19c5d54a2" {
		t.Fatalf("provisioning vector = %s", p.ProvisioningSHA256)
	}
	raw, _ := json.Marshal(p)
	if _, err := DecodeProvisioningRecord(raw); err != nil {
		t.Fatal(err)
	}
	p.Mode = "unknown"
	if err := p.Validate(); err == nil {
		t.Fatal("unknown provisioning mode accepted")
	}
	p = ProvisioningRecord{APIVersion: ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: digest(), AuthenticationEvidenceSHA256: digest(), EvidenceClass: EvidenceProduction, ProvisioningSHA256: digest()}
	if p.ComputedSHA256() == "" {
		t.Fatal("empty provisioning hash")
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(p)
	if _, err := DecodeProvisioningRecord(raw); err == nil {
		t.Fatal("tampered provisioning self hash accepted")
	}
}

func TestDescriptorSchemaParityOracle(t *testing.T) {
	rawSchema, err := os.ReadFile("../../schema/bootstrap-descriptor.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(strings.NewReader(string(rawSchema)))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	if err := c.AddResource("https://schemas.invalid/bootstrap-descriptor.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("https://schemas.invalid/bootstrap-descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := testDescriptor(t)
	check := func(d DescriptorDocument) error {
		b, _ := json.Marshal(d)
		return schema.Validate(jsonValueForSchema(t, b))
	}
	if err := check(valid); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	valid.PublisherScopes[0].TemplatePath = "."
	if !validPathIdentity(valid.PublisherScopes[0].TemplatePath) {
		t.Fatal("runtime rejected root template path")
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("runtime descriptor validation rejected root template path: %v", err)
	}
	if err := check(valid); err != nil {
		t.Fatalf("schema rejected root template path: %v", err)
	}
	unicodePath := strings.Repeat("т", 1024)
	valid.PublisherScopes[0].TemplatePath = unicodePath
	if !validPathIdentity(unicodePath) {
		t.Fatal("runtime rejected valid Unicode path boundary")
	}
	if err := check(valid); err != nil {
		t.Fatalf("schema rejected valid Unicode path boundary: %v", err)
	}
	tooLong := valid
	tooLong.PublisherScopes[0].TemplatePath = strings.Repeat("т", 1025)
	if validPathIdentity(tooLong.PublisherScopes[0].TemplatePath) {
		t.Fatal("runtime accepted oversized Unicode path")
	}
	if err := check(tooLong); err == nil {
		t.Fatal("schema accepted oversized Unicode path")
	}
	valid = testDescriptor(t)
	invalid := valid
	invalid.AllowedPolicyOrigins = append(invalid.AllowedPolicyOrigins, invalid.AllowedPolicyOrigins[0])
	if err := check(invalid); err == nil {
		t.Fatal("duplicate policy origin accepted by schema")
	}
	invalid = valid
	invalid.Anchors = append(invalid.Anchors, invalid.Anchors[0])
	if err := check(invalid); err == nil {
		t.Fatal("duplicate anchor accepted by schema")
	}
	invalid = valid
	invalid.Threshold = 2
	if err := check(invalid); err == nil {
		t.Fatal("threshold above anchor count accepted by schema")
	}
	for _, path := range []string{"..", "../escape", "./escape", "templates/.", "templates/..", "templates/./base", "templates/../base", "/templates", "templates/", "templates//base", `templates\\base`, "templates:base"} {
		invalid = valid
		invalid.PublisherScopes[0].TemplatePath = path
		if validPathIdentity(path) {
			t.Fatalf("runtime accepted unsafe template path %q", path)
		}
		if err := invalid.Validate(); err == nil {
			t.Fatalf("runtime descriptor validation accepted unsafe template path %q", path)
		}
		if err := check(invalid); err == nil {
			t.Fatalf("schema accepted unsafe template path %q", path)
		}
	}
}

func jsonValueForSchema(t *testing.T, raw []byte) any {
	t.Helper()
	v, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestProvisioningAndStateSchemaOracle(t *testing.T) {
	for _, tc := range []struct {
		path  string
		value any
	}{
		{"../../schema/bootstrap-provisioning.v1.schema.json", func() ProvisioningRecord {
			p := ProvisioningRecord{APIVersion: ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: digest(), AuthenticationEvidenceSHA256: digest(), EvidenceClass: EvidenceSimulated}
			p.ProvisioningSHA256 = p.ComputedSHA256()
			return p
		}()},
		{"../../schema/oss-accepted-state.v1.schema.json", testAcceptedState()},
	} {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := js.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		c := js.NewCompiler()
		if err := c.AddResource("https://schemas.invalid/"+tc.path, doc); err != nil {
			t.Fatal(err)
		}
		schema, err := c.Compile("https://schemas.invalid/" + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(tc.value)
		if err := schema.Validate(jsonValueForSchema(t, b)); err != nil {
			t.Fatalf("%s valid instance rejected: %v", tc.path, err)
		}
	}
}
