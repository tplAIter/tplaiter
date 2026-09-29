package update

import (
	"path/filepath"
	"testing"
)

func TestScanConflictsFindsMarkers(t *testing.T) {
	dir := t.TempDir()
	writeWork(t, dir, "clean.go", "package x\n")
	writeWork(t, dir, "conflicted.go", "package x\n"+markerOurs+"\nlocal\n"+markerSeparator+"\ntpl\n"+markerTheirs+"\n")
	// Excluded directories must not appear in the result.
	writeWork(t, dir, ".tplaiter/baseline.json", markerOurs+"\n")
	writeWork(t, dir, "docs/example.md", markerOurs+" docs example\n")

	found, err := ScanConflicts(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0] != "conflicted.go" {
		t.Errorf("ScanConflicts = %v, want [conflicted.go]", found)
	}
}

func TestScanConflictsClean(t *testing.T) {
	dir := t.TempDir()
	writeWork(t, dir, "a.go", "package a\n")
	writeWork(t, dir, "sub/b.go", "package b\n")

	found, err := ScanConflicts(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("expected no conflicts, got %v", found)
	}
}

func TestScanConflictsSkipsBinary(t *testing.T) {
	dir := t.TempDir()
	// Binary file with NUL in the first block and a marker-like line afterward.
	full := filepath.Join(dir, "bin.dat")
	if err := writeFile(full, append([]byte{0, 1, 2}, []byte("\n"+markerOurs+"\n")...)); err != nil {
		t.Fatal(err)
	}
	found, err := ScanConflicts(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("binary file must be skipped, got %v", found)
	}
}
