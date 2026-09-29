package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const ProfileBindingAPIVersion = "tplaiter.dev/trust-profile-binding/v1"

type ProfileID string

const (
	ProfileOSS          ProfileID = "oss"
	ProfileDevelopment  ProfileID = "development"
	ProfileOrganization ProfileID = "organization"
)

type Assurance string

const (
	PublisherVerified     Assurance = "publisher-verified"
	DevelopmentUnverified Assurance = "development-unverified"
	OrganizationProtected Assurance = "organization-protected"
)

type EvidenceClass string

const (
	EvidenceProduction EvidenceClass = "production"
	EvidenceSimulated  EvidenceClass = "simulated"
)

// ProfileBinding is an assertion carried by artifacts. It never creates an Authority.
type ProfileBinding struct {
	APIVersion        string        `json:"apiVersion"`
	ID                ProfileID     `json:"id"`
	DefinitionVersion uint32        `json:"definitionVersion"`
	ConfigSHA256      string        `json:"configSHA256"`
	PolicySHA256      string        `json:"policySHA256"`
	AuthoritySHA256   string        `json:"authoritySHA256"`
	Assurance         Assurance     `json:"assurance"`
	EvidenceClass     EvidenceClass `json:"evidenceClass"`
}

func DecodeProfileBinding(raw []byte) (*ProfileBinding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return nil, ErrProfileInvalid
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrProfileInvalid
	}
	for _, key := range []string{"apiVersion", "id", "definitionVersion", "configSHA256", "policySHA256", "authoritySHA256", "assurance", "evidenceClass"} {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("%w: missing required field %q", ErrProfileInvalid, key)
		}
	}
	var value ProfileBinding
	if err := canonicaljson.DecodeStrict(raw, &value); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProfileInvalid, err)
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return &value, nil
}

func (p ProfileBinding) Validate() error {
	if p.APIVersion != ProfileBindingAPIVersion || p.DefinitionVersion != 1 {
		return ErrProfileInvalid
	}
	if !validDigest(p.ConfigSHA256) || !validDigest(p.PolicySHA256) || !validDigest(p.AuthoritySHA256) {
		return fmt.Errorf("%w: invalid digest", ErrProfileInvalid)
	}
	if p.EvidenceClass != EvidenceProduction && p.EvidenceClass != EvidenceSimulated {
		return ErrProfileInvalid
	}
	switch p.ID {
	case ProfileOSS:
		if p.Assurance != PublisherVerified {
			return ErrProfileInvalid
		}
	case ProfileDevelopment:
		if p.Assurance != DevelopmentUnverified {
			return ErrProfileInvalid
		}
	case ProfileOrganization:
		if p.Assurance != OrganizationProtected {
			return ErrProfileInvalid
		}
		if p.EvidenceClass != EvidenceProduction {
			return fmt.Errorf("%w: simulated organization evidence", ErrProfileInvalid)
		}
	default:
		return ErrProfileInvalid
	}
	return nil
}

func (p ProfileBinding) Equal(other ProfileBinding) bool { return p == other }

var (
	ErrProfileInvalid  = errors.New("bootstrap: TRUST_PROFILE_INVALID")
	ErrProfileMismatch = errors.New("bootstrap: TRUST_PROFILE_MISMATCH")
	ErrDowngradeDenied = errors.New("bootstrap: TRUST_DOWNGRADE_DENIED")
)

func RequireProfile(minimum, requested ProfileID) error {
	if !validProfileID(minimum) || !validProfileID(requested) {
		return ErrProfileInvalid
	}
	if minimum == ProfileOrganization && requested != ProfileOrganization {
		return ErrDowngradeDenied
	}
	return nil
}

func validProfileID(id ProfileID) bool {
	return id == ProfileOSS || id == ProfileDevelopment || id == ProfileOrganization
}
