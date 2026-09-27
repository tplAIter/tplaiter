package bootstrap

import (
	"encoding/json"
	"testing"
)

func testAcceptedState() OSSAcceptedState {
	s := OSSAcceptedState{APIVersion: OSSAcceptedStateAPIVersion, DescriptorSHA256: digest(), ProvisioningSHA256: digest(), AuthorityID: "synthetic-authority", Sequence: 1, EnvelopePayloadSHA256: digest(), RevocationEpoch: 0, ReceiptDigest: digest(), TreeSize: 1, CheckpointDigest: digest()}
	s.StateSHA256 = s.ComputedSHA256()
	return s
}

func TestOSSAcceptedStateRoundTripAndBounds(t *testing.T) {
	s := testAcceptedState()
	if got := s.ComputedSHA256(); got != "sha256:b9878d31ea853f7d3075fcd5c85796e4982694ef09f2aaba7c2eb578e0f812e3" {
		t.Fatalf("state vector = %s", got)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOSSAcceptedState(raw); err != nil {
		t.Fatal(err)
	}
	s.Sequence = maxSafeInteger
	s.TreeSize = maxSafeInteger
	s.StateSHA256 = s.ComputedSHA256()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Sequence = maxSafeInteger + 1
	if err := s.Validate(); err == nil {
		t.Fatal("sequence above safe integer accepted")
	}
}

func TestOSSAcceptedStateRejectsMissingOrTamperedFields(t *testing.T) {
	s := testAcceptedState()
	raw, _ := json.Marshal(s)
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "checkpointDigest")
	raw, _ = json.Marshal(object)
	if _, err := DecodeOSSAcceptedState(raw); err == nil {
		t.Fatal("missing state field accepted")
	}
	s = testAcceptedState()
	s.AuthorityID = "other-authority"
	raw, _ = json.Marshal(s)
	if _, err := DecodeOSSAcceptedState(raw); err == nil {
		t.Fatal("tampered state self hash accepted")
	}
}
