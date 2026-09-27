package evidencecas

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFSReaderReadsAndDetectsTamper(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blob := []byte("repeat-verifiable evidence")
	digest := Digest(blob)
	path := blobPath(root, digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewFSReader(physicalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Read(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(blob) {
		t.Fatalf("got %q", got)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(context.Background(), digest); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestFSReaderRejectsSymlinkAndUnsafeDigest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blob := []byte("outside")
	digest := Digest(blob)
	path := blobPath(root, digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	reader, err := NewFSReader(physicalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(context.Background(), digest); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := reader.Read(context.Background(), "sha256:../../etc/passwd"); err == nil {
		t.Fatal("unsafe digest accepted")
	}
}

func TestFSReaderRejectsSymlinkAncestor(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	physical := filepath.Join(parent, "physical")
	if err := os.MkdirAll(filepath.Join(physical, "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	aliased := filepath.Join(parent, "alias")
	if err := os.Symlink(physical, aliased); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := NewFSReader(filepath.Join(aliased, "sha256")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
}

func TestFSReaderDoesNotWrite(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sha256", "00"), 0o700); err != nil {
		t.Fatal(err)
	}
	reader, err := NewFSReader(physicalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	missing := "sha256:" + strings.Repeat("0", 64)
	if _, err := reader.Read(context.Background(), missing); err == nil {
		t.Fatal("missing blob accepted")
	}
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("store changed: before=%d after=%d", len(before), len(after))
	}
}

func TestFSReaderRejectsOversizeAndCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	oversize := make([]byte, maxBlobSize+1)
	digest := Digest(oversize)
	path := blobPath(root, digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewFSReader(physicalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(context.Background(), digest); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversize error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.Read(canceled, digest); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestFSReaderCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	reader, err := NewFSReader(physicalPath(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(context.Background(), "sha256:"+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("read after close = %v", err)
	}
}

func blobPath(root, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(root, "sha256", hexDigest[:2], hexDigest[2:])
}

func physicalPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
