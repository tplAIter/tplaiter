package evidencecas

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestReadBoundedCapsAndLifetime(t *testing.T) {
	root := physicalPath(t.TempDir())
	blob := []byte("bounded public evidence")
	ref := Digest(blob)
	path := blobPath(root, ref)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewFSReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, maximum := range []int64{-1, 0, int64(len(blob) - 1)} {
		got, err := r.ReadBounded(context.Background(), ref, maximum)
		if !errors.Is(err, ErrBoundExceeded) || got != nil {
			t.Fatalf("cap %d: %x %v", maximum, got, err)
		}
	}
	for _, maximum := range []int64{int64(len(blob)), maxBlobSize, 1 << 62} {
		got, err := r.ReadBounded(context.Background(), ref, maximum)
		if err != nil || !bytes.Equal(got, blob) || len(got) != cap(got) {
			t.Fatalf("exact bounded body: %x %v", got, err)
		}
	}
	// Negative/over-cap rejection precedes hashing: a sparse oversized object
	// under this small reference must reject the physical size, not read/hash it.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxBlobSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got, err := r.ReadBounded(context.Background(), ref, 1<<62); got != nil || !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("16MiB ceiling: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ReadBounded(ctx, ref, maxBlobSize); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.ReadBounded(nil, ref, 1); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := r.ReadBounded(context.Background(), "sha256:../../outside", 1); err == nil {
		t.Fatal("unsafe reference accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadBounded(context.Background(), ref, 1); err == nil {
		t.Fatal("closed owner accepted")
	}
	if _, err := (*FSReader)(nil).ReadBounded(context.Background(), ref, 1); err == nil {
		t.Fatal("nil owner accepted")
	}
}

func TestReadBoundedEmptyAndDigest(t *testing.T) {
	root := physicalPath(t.TempDir())
	ref := Digest(nil)
	path := blobPath(root, ref)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewFSReader(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.ReadBounded(context.Background(), ref, 0)
	if err != nil || len(got) != 0 || cap(got) != 0 {
		t.Fatalf("empty: %x %v", got, err)
	}
	if err := os.WriteFile(path, []byte("same-size tamper"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadBounded(context.Background(), ref, 100); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tamper: %v", err)
	}
}

func TestReadBoundedUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		t.Skip("strict descriptor platform")
	}
	if _, err := (&casRoot{}).readBounded(context.Background(), strings.Repeat("0", 64), 0); !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatal(err)
	}
}
