//go:build !darwin && !linux

package trustload

type storeVFS struct{}

func newStoreVFS(*rootLease, storeMode) (*storeVFS, error) { return nil, ErrProvenanceUnavailable }
func newStoreVFSObserved(*rootLease, storeMode, *storeProofObserver) (*storeVFS, error) {
	return nil, ErrProvenanceUnavailable
}
func (v *storeVFS) dsn() string  { return "" }
func (v *storeVFS) Close() error { return ErrProvenanceUnavailable }
