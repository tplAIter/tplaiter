package bootstrap

import "errors"

const OSSAcceptedStateAPIVersion = "tplaiter.dev/oss-accepted-state/v1"

type OSSAcceptedState struct {
	APIVersion            string `json:"apiVersion"`
	DescriptorSHA256      string `json:"descriptorSHA256"`
	ProvisioningSHA256    string `json:"provisioningSHA256"`
	AuthorityID           string `json:"authorityId"`
	Sequence              uint64 `json:"sequence"`
	EnvelopePayloadSHA256 string `json:"envelopePayloadSHA256"`
	RevocationEpoch       uint64 `json:"revocationEpoch"`
	ReceiptDigest         string `json:"receiptDigest"`
	TreeSize              uint64 `json:"treeSize"`
	CheckpointDigest      string `json:"checkpointDigest"`
	StateSHA256           string `json:"stateSHA256"`
}

var stateFields = []string{"apiVersion", "descriptorSHA256", "provisioningSHA256", "authorityId", "sequence", "envelopePayloadSHA256", "revocationEpoch", "receiptDigest", "treeSize", "checkpointDigest", "stateSHA256"}

func DecodeOSSAcceptedState(raw []byte) (*OSSAcceptedState, error) {
	if len(raw) > maxBootstrapDocument {
		return nil, errors.New("bootstrap: accepted state exceeds size limit")
	}
	var s OSSAcceptedState
	if err := decodeBootstrapDocument(raw, stateFields, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.StateSHA256 != s.ComputedSHA256() {
		return nil, errors.New("bootstrap: accepted state digest mismatch")
	}
	return &s, nil
}

func (s OSSAcceptedState) Validate() error {
	if s.APIVersion != OSSAcceptedStateAPIVersion || !validDigest(s.DescriptorSHA256) || !validDigest(s.ProvisioningSHA256) || !validDescriptorToken(s.AuthorityID, 256) || s.Sequence == 0 || s.Sequence > maxSafeInteger || !validDigest(s.EnvelopePayloadSHA256) || s.RevocationEpoch > maxSafeInteger || !validDigest(s.ReceiptDigest) || s.TreeSize == 0 || s.TreeSize > maxSafeInteger || !validDigest(s.CheckpointDigest) || !validDigest(s.StateSHA256) {
		return errors.New("bootstrap: invalid accepted state")
	}
	return nil
}
func (s OSSAcceptedState) ComputedSHA256() string { return stateDigest(s) }
func stateDigest(s OSSAcceptedState) string {
	return bootstrapDigest(OSSAcceptedStateAPIVersion, struct {
		APIVersion   string `json:"apiVersion"`
		Descriptor   string `json:"descriptorSHA256"`
		Provisioning string `json:"provisioningSHA256"`
		Authority    string `json:"authorityId"`
		Sequence     uint64 `json:"sequence"`
		Envelope     string `json:"envelopePayloadSHA256"`
		Epoch        uint64 `json:"revocationEpoch"`
		Receipt      string `json:"receiptDigest"`
		Tree         uint64 `json:"treeSize"`
		Checkpoint   string `json:"checkpointDigest"`
	}{s.APIVersion, s.DescriptorSHA256, s.ProvisioningSHA256, s.AuthorityID, s.Sequence, s.EnvelopePayloadSHA256, s.RevocationEpoch, s.ReceiptDigest, s.TreeSize, s.CheckpointDigest})
}
