package bootstrap

import (
	"context"
	"encoding/json"
	"testing"
)

func TestVerifyOSSTransparencyWirePositiveAndMissingLeafIndex(t *testing.T) {
	v, ext, candidate, _ := externalFixture(t, ProfileOSS)
	if _, err := v.VerifyOSS(context.Background(), ext, candidate); err != nil {
		t.Fatalf("valid index-zero inclusion proof rejected: %v", err)
	}

	store, ok := v.store.(memoryEvidence)
	if !ok {
		t.Fatal("fixture store has unexpected type")
	}
	var proof map[string]any
	if err := json.Unmarshal(store[candidate.Transparency.InclusionProofCAS], &proof); err != nil {
		t.Fatal(err)
	}
	delete(proof, "leafIndex")
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	badRef := put(store, proof)
	if string(raw) != string(store[badRef]) {
		t.Fatal("fixture proof was not stored canonically")
	}
	candidate.Transparency.InclusionProofCAS = badRef
	if got, err := v.VerifyOSS(context.Background(), ext, candidate); got != nil || err == nil {
		t.Fatalf("omitted leafIndex accepted by VerifyOSS: authority=%v err=%v", got, err)
	}
}

func TestVerifyDevelopmentTransparencyWirePositiveAndMissingLeafIndex(t *testing.T) {
	v, _, protected, _ := newProtectedFixture(t)
	var envelope Envelope
	if err := json.Unmarshal(protected.snapshot.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures = []Signature{}
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	in := DevelopmentInputs{Envelope: rawEnvelope, Transparency: protected.snapshot.Transparency}
	if got, err := v.VerifyDevelopment(context.Background(), in); got == nil || err != nil {
		t.Fatalf("valid index-zero inclusion proof rejected by VerifyDevelopment: context=%v err=%v", got, err)
	}

	store, ok := v.store.(memoryEvidence)
	if !ok {
		t.Fatal("fixture store has unexpected type")
	}
	var proof map[string]any
	if err := json.Unmarshal(store[in.Transparency.InclusionProofCAS], &proof); err != nil {
		t.Fatal(err)
	}
	delete(proof, "leafIndex")
	badRef := put(store, proof)
	in.Transparency.InclusionProofCAS = badRef
	if got, err := v.VerifyDevelopment(context.Background(), in); got != nil || err == nil {
		t.Fatalf("omitted leafIndex accepted by VerifyDevelopment: context=%v err=%v", got, err)
	}
}
