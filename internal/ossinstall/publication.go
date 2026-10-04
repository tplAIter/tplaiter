package ossinstall

import "errors"

// ErrPublicationUnsupported refuses publication when a platform or filesystem
// cannot guarantee native atomic no-replace rename. There is no overwrite fallback.
var ErrPublicationUnsupported = errors.New("ossinstall: exclusive atomic installation publication unavailable")

// ErrPublicationCommitted means publication crossed the no-replace rename
// boundary but durable finalization or pin output could not be confirmed.
var ErrPublicationCommitted = errors.New("ossinstall: installation committed; verify this installation before linking or retrying")

type PublicationCommittedError struct{ Cause error }

func (e *PublicationCommittedError) Error() string {
	return ErrPublicationCommitted.Error() + ": " + e.Cause.Error()
}
func (e *PublicationCommittedError) Unwrap() error        { return e.Cause }
func (e *PublicationCommittedError) Is(target error) bool { return target == ErrPublicationCommitted }

// Test-only failure seam, never an authority/configuration input.
var publicationFinalizationHook func() error
