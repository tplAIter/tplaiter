//go:build !darwin && !linux

package trustload

// Unsupported platforms fail closed. Production secure filesystem loading on
// those platforms is a separately gated platform adapter.
func secureReadFile(string, int) ([]byte, error) { return nil, ErrProvenanceUnavailable }
