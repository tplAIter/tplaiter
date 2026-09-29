package trustload

import (
	"runtime"
	"testing"
)

// requireNativeStore is the only platform gate left in the store tests, and
// it applies only to files without a darwin||linux build constraint. The
// secure store is implemented and proven on Darwin (APFS) and Linux (ext4,
// overlayfs); on every other host (Windows and the BSDs are deferred, see
// tp-6v4) the package compiles with fail-closed stubs and these store-backed
// scenarios cannot run.
func requireNativeStore(t *testing.T) {
	t.Helper()
	if !storePlatformAvailable() {
		t.Skip("trust store is not implemented on " + runtime.GOOS + " (deferred platform)")
	}
}
