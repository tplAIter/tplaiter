package mcpsrv

import "testing"

// TestKnownCLIErrorRecognizesWholeTrustLines pins the fixed trust diagnostic
// lines the transport forwards as typed codes, and proves that any other
// stderr (extra text, a different prefix) is never forwarded.
func TestKnownCLIErrorRecognizesWholeTrustLines(t *testing.T) {
	for stderr, want := range map[string]string{
		"error: trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED\n":                     "TRUST_STORE_FILESYSTEM_UNSUPPORTED",
		"error: trustload: TRUST_ANCHOR_MISSING\n":                                   "TRUST_ANCHOR_MISSING",
		"error: TRUST_LIFECYCLE_UNAVAILABLE\n":                                       "TRUST_LIFECYCLE_UNAVAILABLE",
		"error: trustload: TRUST_PROVENANCE_UNAVAILABLE\nTRUST_ACTION_UNAVAILABLE\n": "TRUST_ACTION_UNAVAILABLE",
		"error: trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED on /secret\n":          "",
		"warning: trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED\n":                   "",
		"error: trustload: TRUST_STORE_FILESYSTEM_UNSUPPORTED":                       "",
	} {
		if got := knownCLIError(stderr); got != want {
			t.Errorf("knownCLIError(%q)=%q, want %q", stderr, got, want)
		}
	}
}
