//go:build !darwin && !linux

package trustload

type objectRoot struct{}

func openObjectRoot(string) (*objectRoot, error) { return nil, ErrProvenanceUnavailable }
func (*objectRoot) read(string) ([]byte, error)  { return nil, ErrProvenanceUnavailable }
func (*objectRoot) Close() error                 { return nil }
