package trustload

// ErrStoreFilesystemUnsupported reports that the trust-store root lives on a
// filesystem family whose locking and durability semantics have not been
// proven for the store (see storeFilesystemSupported). It is a refinement of
// ErrProvenanceUnavailable: errors.Is(err, ErrProvenanceUnavailable) stays
// true, so every existing fail-closed branch treats it identically, while the
// message carries the precise typed code for operators.
var ErrStoreFilesystemUnsupported error = storeFilesystemUnsupportedError{}

type storeFilesystemUnsupportedError struct{}

func (storeFilesystemUnsupportedError) Error() string {
	return "trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED"
}

// Is makes the typed code match the generic provenance-unavailable sentinel.
func (storeFilesystemUnsupportedError) Is(target error) bool {
	return target == ErrProvenanceUnavailable
}
