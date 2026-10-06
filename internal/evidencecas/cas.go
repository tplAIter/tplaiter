// Package evidencecas provides read-only access to repeat-verifiable evidence.
package evidencecas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

const (
	digestPrefix = "sha256:"
	maxBlobSize  = 16 << 20
)

type Reader interface {
	Read(context.Context, string) ([]byte, error)
}

// FSReader owns a pinned filesystem root. Close waits for active reads and is idempotent.
type FSReader struct {
	mu     sync.RWMutex
	root   *casRoot
	closed bool
}

func NewFSReader(root string) (*FSReader, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("evidencecas: resolve root: %w", err)
	}
	if filepath.Clean(abs) != abs {
		return nil, errors.New("evidencecas: root must be a clean path")
	}
	pinned, err := openCASRoot(abs)
	if err != nil {
		return nil, err
	}
	return &FSReader{root: pinned}, nil
}

func Digest(blob []byte) string {
	sum := sha256.Sum256(blob)
	return digestPrefix + hex.EncodeToString(sum[:])
}

func (r *FSReader) Read(ctx context.Context, digest string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("evidencecas: nil reader")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.root == nil {
		return nil, errors.New("evidencecas: reader is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("evidencecas: read canceled: %w", err)
	}
	h, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	blob, err := r.root.read(h)
	if err != nil {
		return nil, fmt.Errorf("evidencecas: read %s: %w", digest, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("evidencecas: read canceled: %w", err)
	}
	if actual := Digest(blob); actual != digest {
		return nil, fmt.Errorf("evidencecas: digest mismatch for %s", digest)
	}
	return blob, nil
}

func (r *FSReader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.root == nil {
		return nil
	}
	err := r.root.close()
	r.root = nil
	return err
}

func parseDigest(digest string) (string, error) {
	if !strings.HasPrefix(digest, digestPrefix) || len(digest) != len(digestPrefix)+sha256.Size*2 {
		return "", fmt.Errorf("evidencecas: invalid digest %q", digest)
	}
	h := strings.TrimPrefix(digest, digestPrefix)
	if strings.ToLower(h) != h {
		return "", fmt.Errorf("evidencecas: non-canonical digest %q", digest)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("evidencecas: invalid digest %q", digest)
	}
	return h, nil
}

// ErrBoundExceeded indicates that a blob cannot fit the caller's byte cap.
var ErrBoundExceeded = errors.New("evidencecas: bounded read exceeds byte cap")

// ErrBlobChanged indicates an inconsistent size, identity or content observation.
var ErrBlobChanged = errors.New("evidencecas: blob changed during bounded read")

// ErrPlatformUnsupported indicates that strict bounded descriptor reads are unavailable.
var ErrPlatformUnsupported = errors.New("evidencecas: bounded descriptor reads unsupported")

// ReadBounded verifies a raw blob without allocating beyond its observed size
// plus one growth sentinel. maximumBytes is a body cap, not a heap budget; the
// existing 16 MiB per-blob ceiling still applies. It never falls back to Read.
func (r *FSReader) ReadBounded(ctx context.Context, digest string, maximumBytes int64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("evidencecas: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maximumBytes < 0 {
		return nil, ErrBoundExceeded
	}
	if r == nil {
		return nil, errors.New("evidencecas: nil reader")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.root == nil {
		return nil, errors.New("evidencecas: reader is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	blob, err := r.root.readBounded(ctx, h, maximumBytes)
	if err != nil {
		return nil, fmt.Errorf("evidencecas: bounded read %s: %w", digest, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if Digest(blob) != digest {
		return nil, fmt.Errorf("evidencecas: digest mismatch for %s", digest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return blob, nil
}
