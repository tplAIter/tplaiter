package newcmd

import "testing"

// TestCheckTplaterVersionDevBuilds verifies that dev builds (ldflags dev, a
// VCS pseudo-version, and +dirty) pass the version gate.
func TestCheckTplaterVersionDevBuilds(t *testing.T) {
	t.Parallel()
	for _, ver := range []string{
		"dev",
		"v0.0.0-20260711135833-cf1d182ebe70+dirty",
		"v0.0.0-20260711135833-cf1d182ebe70",
		"v1.2.3+dirty",
	} {
		if err := checkTplaterVersion(">=0.1.0", ver); err != nil {
			t.Errorf("version %q must pass the gate: %v", ver, err)
		}
	}
	if err := checkTplaterVersion(">=0.1.0", "v0.0.1"); err == nil {
		t.Error("v0.0.1 must not pass the >=0.1.0 gate")
	}
}
