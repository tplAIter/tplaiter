package e2e

import "testing"

// TestMiscCommandsExitZero — table of commands without side effects on state
// (scenario 5, implementation requirement): doctor / version / help must
// succeed on any machine with go+git in PATH (doctor.go:
// doctorCriticalTools specifically requires go and git — both are required to
// build the test binary itself, so there can be no critical failures here).
func TestMiscCommandsExitZero(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{"doctor", []string{"doctor"}},
		{"version", []string{"version"}},
		{"help", []string{"help"}},
		{"root_help_flag", []string{"--help"}},
		{"completion_bash", []string{"completion", "bash"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := newHome(t)
			res := mustRun(t, home, "", tc.args...)
			if res.Stdout == "" && res.Stderr == "" {
				t.Errorf("tplater %v: empty output on both stdout and stderr", tc.args)
			}
		})
	}
}

// TestVersionReportsBuildVersion verifies that `tplater version` prints
// EXACTLY the version compiled in by ldflags in TestMain (buildVersion) — the
// only guarantee that scenario 3's version gate (requires.tplaiter) checks the
// intended value rather than a "dev" stub (see main_test.go:buildVersion).
func TestVersionReportsBuildVersion(t *testing.T) {
	t.Parallel()
	home := newHome(t)
	res := mustRun(t, home, "", "version")
	mustContain(t, res.Stdout, buildVersion, "tplater version")
}
