package cmd

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

type doctorSpyRunner struct{ calls int }

func (r *doctorSpyRunner) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	r.calls++
	return execx.Result{}, nil
}

func (r *doctorSpyRunner) LookPath(string) (string, error) {
	r.calls++
	return "", nil
}

func TestDoctorReportIsDescriptiveAndDoesNotRunProbe(t *testing.T) {
	spy := new(doctorSpyRunner)
	sections, critical := buildDoctorReport(context.Background(), spy, "CANARY-cwd", "CANARY-home")
	if critical || spy.calls != 0 {
		t.Fatalf("doctor report critical=%v calls=%d, want descriptive no-run", critical, spy.calls)
	}
	if len(sections) != 1 || len(sections[0].Rows) != 1 || sections[0].Rows[0].Status != rowWarn {
		t.Fatalf("doctor sections = %#v, want one unverified row", sections)
	}
}
