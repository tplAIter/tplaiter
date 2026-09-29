//go:build !darwin && !linux

package trustload

import "context"

// The unsupported stub has the structural fields read by generic refresh
// identity checks. openRootLease remains fail-closed and never returns this
// capability, so the zero identities cannot authorize a filesystem route.
type rootLease struct {
	dev, ino uint64
	mode     storeMode
}

// Tests and callers use this only to skip native filesystem assertions.
func storePlatformAvailable() bool { return false }

func openRootLease(context.Context, string, storeMode) (*rootLease, error) {
	return nil, ErrProvenanceUnavailable
}
func (r *rootLease) closedState() bool                 { return true }
func (r *rootLease) valid() bool                       { return false }
func (r *rootLease) pendingSidecar() error             { return ErrProvenanceUnavailable }
func (r *rootLease) markerExists(string) (bool, error) { return false, ErrProvenanceUnavailable }
func (r *rootLease) hasLeaf(string) (bool, error)      { return false, ErrProvenanceUnavailable }
func (r *rootLease) readMarker(context.Context, string, int) ([]byte, error) {
	return nil, ErrProvenanceUnavailable
}

func (r *rootLease) readMarkerSnapshot(context.Context, string, int) ([]byte, markerSnapshot, error) {
	return nil, markerSnapshot{}, ErrProvenanceUnavailable
}

func (r *rootLease) writePendingMarker(context.Context, []byte) error {
	return ErrProvenanceUnavailable
}

func (r *rootLease) activatePendingMarker(context.Context, []byte) error {
	return ErrProvenanceUnavailable
}

func recoverStoreColdJournal(context.Context, *rootLease) error {
	return ErrProvenanceUnavailable
}
func (r *rootLease) Close() error { return ErrProvenanceUnavailable }
