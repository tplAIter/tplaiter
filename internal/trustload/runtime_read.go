package trustload

import (
	"context"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
)

// Read implements evidencecas.Reader for raw lifecycle evidence through the
// fixed CAS authenticated and opened by this runtime's constructor. Bootstrap
// trust-store blobs are a separate namespace, not an evidence-origin fallback.
// Close waits for reads; no reader, root path or lifetime escapes the runtime.
func (r *Runtime) Read(ctx context.Context, ref string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrProvenanceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrProvenanceUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.evidence == nil {
		return nil, ErrProvenanceUnavailable
	}
	raw, err := r.evidence.Read(ctx, ref)
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}

// ReadBounded reads only the runtime-owned lifecycle CAS with an explicit body
// cap. The held runtime mutex covers the descriptor read and exact-size clone;
// callers must budget the reader body/sentinel and this detached copy separately.
func (r *Runtime) ReadBounded(ctx context.Context, ref string, maximumBytes int64) ([]byte, error) {
	if ctx == nil {
		return nil, ErrProvenanceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrProvenanceUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.evidence == nil {
		return nil, ErrProvenanceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := r.evidence.ReadBounded(ctx, ref, maximumBytes)
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	if err != nil {
		return nil, err
	}
	if maximumBytes < 0 || int64(len(raw)) > maximumBytes {
		return nil, evidencecas.ErrBoundExceeded
	}
	copyOfRaw := make([]byte, len(raw))
	copy(copyOfRaw, raw)
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	return copyOfRaw, nil
}
