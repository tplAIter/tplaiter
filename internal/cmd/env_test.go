package cmd

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvSetupDirectIngressDenied(t *testing.T) {
	spy := new(doctorSpyRunner)
	old := envRunner
	envRunner = spy
	t.Cleanup(func() { envRunner = old })
	c := newEnvSetupCmd()
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"--yes"})
	if err := c.Execute(); !errors.Is(err, ErrActionUnavailable) {
		t.Fatalf("env setup = %v, want typed denial", err)
	}
	if spy.calls != 0 {
		t.Fatalf("env setup touched runner before denial: %d calls", spy.calls)
	}
}
