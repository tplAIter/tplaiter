package trustload

import (
	"context"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

type OperatorPinRecord struct {
	APIVersion       string `json:"apiVersion"`
	Method           string `json:"method"`
	DescriptorSHA256 string `json:"descriptorSHA256"`
}

var operatorFields = []string{"apiVersion", "method", "descriptorSHA256"}

func DecodeOperatorPinRecord(raw []byte) (*OperatorPinRecord, error) {
	if len(raw) == 0 || len(raw) > maxDocument {
		return nil, ErrConfigInvalid
	}
	if err := requiredObjectFields(raw, operatorFields); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
	}
	var v OperatorPinRecord
	if err := canonicaljson.DecodeStrict(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
	}
	if v.APIVersion != OperatorPinRecordAPIVersion || v.Method != "operator-pinned" || !digest(v.DescriptorSHA256) {
		return nil, ErrConfigInvalid
	}
	return &v, nil
}

// LaunchSelection is fixed by the installed launcher. It deliberately has no
// constructor from JSON or candidate input.
type LaunchSelection struct {
	Profile        bootstrap.ProfileID
	RuntimeConfig  FilePin
	OperatorRecord FilePin
	InstallationID string
}

func (s LaunchSelection) Validate() error {
	if !validProfile(s.Profile) || !token(s.InstallationID) || !validFilePin(s.RuntimeConfig) || !validFilePin(s.OperatorRecord) {
		return ErrAnchorMissing
	}
	return nil
}

type Loaded struct {
	Install          RuntimeInstall
	Operator         OperatorPinRecord
	DescriptorJSON   []byte
	ProvisioningJSON []byte
	PolicyJSON       []byte
	OperatorJSON     []byte
}

// Load validates fixed installation and operator provenance without creating
// directories, files, databases, network connections, or authority readers.
func Load(ctx context.Context, selection LaunchSelection) (*Loaded, error) {
	if ctx == nil {
		return nil, ErrAnchorMissing
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	configRaw, err := readRaw(selection.RuntimeConfig.Path)
	if err != nil {
		return nil, err
	}
	install, err := DecodeRuntimeInstall(configRaw)
	if err != nil {
		return nil, err
	}
	if install.InstallationID != selection.InstallationID || install.Profile != selection.Profile {
		return nil, ErrPinMismatch
	}
	if d, err := install.Digest(); err != nil || d != selection.RuntimeConfig.SHA256 {
		return nil, ErrPinMismatch
	}
	if install.OperatorRecord != selection.OperatorRecord {
		return nil, ErrPinMismatch
	}
	operatorRaw, err := configFileBytes(install.OperatorRecord)
	if err != nil {
		return nil, err
	}
	operator, err := DecodeOperatorPinRecord(operatorRaw)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	descriptorRaw, err := configFileBytes(install.Descriptor)
	if err != nil {
		return nil, err
	}
	provisioningRaw, err := configFileBytes(install.Provisioning)
	if err != nil {
		return nil, err
	}
	policyRaw, err := configFileBytes(install.ExecutionPolicy)
	if err != nil {
		return nil, err
	}
	descriptor, err := bootstrap.DecodeDescriptorDocument(descriptorRaw)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	provisioning, err := bootstrap.DecodeProvisioningRecord(provisioningRaw)
	if err != nil {
		return nil, ErrProvenanceUnavailable
	}
	if descriptor.Profile != install.Profile || descriptor.DescriptorSHA256 != operator.DescriptorSHA256 || provisioning.Mode != "operator-pinned" || provisioning.DescriptorSHA256 != operator.DescriptorSHA256 || provisioning.AuthenticationEvidenceSHA256 != rawSHA256(operatorRaw) {
		return nil, ErrProvenanceUnavailable
	}
	if provisioning.EvidenceClass != bootstrap.EvidenceSimulated && provisioning.EvidenceClass != bootstrap.EvidenceProduction {
		return nil, ErrProvenanceUnavailable
	}
	if install.Profile == bootstrap.ProfileOrganization {
		return nil, ErrProtectedUnavailable
	}
	return &Loaded{Install: *install, Operator: *operator, DescriptorJSON: clone(descriptorRaw), ProvisioningJSON: clone(provisioningRaw), PolicyJSON: clone(policyRaw), OperatorJSON: clone(operatorRaw)}, nil
}

// LoadRuntime is an alias retained for composition callers that name the
// operation after its returned runtime installation.
func LoadRuntime(ctx context.Context, selection LaunchSelection) (*Loaded, error) {
	return Load(ctx, selection)
}

func clone(v []byte) []byte { return append([]byte(nil), v...) }

func readRaw(path string) ([]byte, error) {
	return secureReadFile(path, maxDocument)
}
