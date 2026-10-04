package trustload

import "context"

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
