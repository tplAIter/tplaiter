package manifest

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"
)

// TestSnapshot_Roundtrip verifies serialization stability: a snapshot read back
// and serialized again matches the original byte for byte. It compares the
// serialized form rather than DeepEqual structures because yaml tags intentionally
// omit omitempty (otherwise `default: false` would be lost), making empty and nil
// input slices indistinguishable after marshaler normalization.
func TestSnapshot_Roundtrip(t *testing.T) {
	orig, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}

	path := filepath.Join(t.TempDir(), SnapshotRelPath)
	if err := SaveSnapshot(path, orig); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	first, err := MarshalTemplate(orig)
	if err != nil {
		t.Fatalf("MarshalTemplate: %v", err)
	}

	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	second, err := MarshalTemplate(got)
	if err != nil {
		t.Fatalf("MarshalTemplate: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("serialization is not stable after roundtrip\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	// Significant normalized structures match (the second load pass).
	got2, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, got2) {
		t.Error("reloading the snapshot produced a different structure")
	}
}

func TestSnapshot_LoadValidates(t *testing.T) {
	// A snapshot passes the same apiVersion/kind gates as a regular manifest.
	orig, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), SnapshotRelPath)
	if err := SaveSnapshot(path, orig); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the manifest restored from the snapshot is invalid: %v", err)
	}
}
