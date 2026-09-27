package cmd

import "testing"

// TestEnvSetupTriState проверяет перевод пары флагов --env-setup/--no-env-setup
// в tri-state *bool: nil (спросить), &true, &false; --no-env-setup имеет
// приоритет при одновременном указании.
func TestEnvSetupTriState(t *testing.T) {
	cases := []struct {
		name             string
		changedEnv       bool
		changedNoEnv     bool
		envSetup, noEnv  bool
		wantNil, wantVal bool
	}{
		{name: "default", wantNil: true},
		{name: "env-setup", changedEnv: true, envSetup: true, wantVal: true},
		{name: "no-env-setup", changedNoEnv: true, noEnv: true, wantNil: false, wantVal: false},
		{name: "both -> no wins", changedEnv: true, changedNoEnv: true, envSetup: true, noEnv: true, wantVal: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newNewCmd()
			if tc.changedEnv {
				_ = c.Flags().Set("env-setup", boolStr(tc.envSetup))
			}
			if tc.changedNoEnv {
				_ = c.Flags().Set("no-env-setup", boolStr(tc.noEnv))
			}
			got := envSetupTriState(c, tc.envSetup, tc.noEnv)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("ожидался nil, получено %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("ожидался %v, получен nil", tc.wantVal)
			}
			if *got != tc.wantVal {
				t.Fatalf("got %v, want %v", *got, tc.wantVal)
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
