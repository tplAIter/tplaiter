package ossinstall

import "errors"

// ErrPublicationUnsupported refuses publication when a platform or filesystem
// cannot guarantee native atomic no-replace rename. There is no overwrite fallback.
var ErrPublicationUnsupported = errors.New("ossinstall: exclusive atomic installation publication unavailable")
