package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
)

func digest() string { return "sha256:" + strings.Repeat("0", 64) }
func TestProfileBindingBranches(t *testing.T) {
	for _, p := range []ProfileBinding{{ProfileBindingAPIVersion, ProfileOSS, 1, digest(), digest(), digest(), PublisherVerified, EvidenceProduction}, {ProfileBindingAPIVersion, ProfileDevelopment, 1, digest(), digest(), digest(), DevelopmentUnverified, EvidenceSimulated}, {ProfileBindingAPIVersion, ProfileOrganization, 1, digest(), digest(), digest(), OrganizationProtected, EvidenceProduction}} {
		if e := p.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	p := ProfileBinding{ProfileBindingAPIVersion, ProfileOrganization, 1, digest(), digest(), digest(), OrganizationProtected, EvidenceSimulated}
	if p.Validate() == nil {
		t.Fatal("simulated organization accepted")
	}
}

func TestDecodeProfileBindingRequiresAllFields(t *testing.T) {
	p := ProfileBinding{APIVersion: ProfileBindingAPIVersion, ID: ProfileOSS, DefinitionVersion: 1, ConfigSHA256: digest(), PolicySHA256: digest(), AuthoritySHA256: digest(), Assurance: PublisherVerified, EvidenceClass: EvidenceProduction}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProfileBinding(raw); err != nil {
		t.Fatal(err)
	}
	raw = []byte(`{"apiVersion":"tplaiter.dev/trust-profile-binding/v1","id":"oss","configSHA256":"` + digest() + `","policySHA256":"` + digest() + `","authoritySHA256":"` + digest() + `","assurance":"publisher-verified","evidenceClass":"production"}`)
	if _, err := DecodeProfileBinding(raw); err == nil {
		t.Fatal("missing zero-valued required definitionVersion accepted")
	}
}

func TestOrganizationCannotDowngrade(t *testing.T) {
	if RequireProfile(ProfileOrganization, ProfileOSS) != ErrDowngradeDenied {
		t.Fatal("downgrade accepted")
	}
}

func TestRequireProfileRejectsUnknownMinimum(t *testing.T) {
	if RequireProfile(ProfileID("unknown"), ProfileOSS) != ErrProfileInvalid {
		t.Fatal("unknown minimum accepted")
	}
}

func TestRequireProfileAcceptsKnownMinimums(t *testing.T) {
	for _, minimum := range []ProfileID{ProfileOSS, ProfileDevelopment, ProfileOrganization} {
		requested := ProfileOSS
		if minimum == ProfileOrganization {
			requested = ProfileOrganization
		}
		if err := RequireProfile(minimum, requested); err != nil {
			t.Fatalf("minimum %q rejected: %v", minimum, err)
		}
	}
}
