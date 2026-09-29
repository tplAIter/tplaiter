package settings

import (
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

func cond(t *testing.T, s string) manifest.Condition {
	t.Helper()
	c, err := manifest.ParseCondition(s)
	if err != nil {
		t.Fatalf("ParseCondition(%q): %v", s, err)
	}
	return c
}

func TestEval_Types(t *testing.T) {
	v := Values{
		"database": "postgres",
		"brokers":  []string{"kafka", "rabbitmq"},
		"toggle":   true,
		"replicas": 3,
		"name":     "svc",
	}
	tests := []struct {
		expr string
		want bool
	}{
		{"database=postgres", true},
		{"database=mysql", false},
		{"database!=mysql", true},
		{"database!=postgres", false},
		{"brokers=kafka", true},                      // multiselect contains
		{"brokers=nats", false},                      // multiselect does not contain
		{"brokers!=nats", true},                      // multiselect does not contain -> !=
		{"brokers!=kafka", false},                    // contains -> != false
		{"toggle=true", true},                        // toggle
		{"toggle=false", false},                      // toggle
		{"toggle!=false", true},                      // toggle negation
		{"replicas=3", true},                         // int
		{"replicas=4", false},                        // int
		{"replicas!=4", true},                        // int negation
		{"name=svc", true},                           // string
		{"name=other", false},                        // string
		{"database=postgres && brokers=kafka", true}, // conjunction
		{"database=postgres && brokers=nats", false}, // conjunction is false
		{"database=postgres && toggle=true && replicas=3", true},
	}
	for _, tc := range tests {
		got, err := Eval(cond(t, tc.expr), v)
		if err != nil {
			t.Errorf("Eval(%q) unexpected error: %v", tc.expr, err)
		}
		if got != tc.want {
			t.Errorf("Eval(%q) = %v, expected %v", tc.expr, got, tc.want)
		}
	}
}

func TestEval_UnknownGroup(t *testing.T) {
	v := Values{"database": "postgres"}
	got, err := Eval(cond(t, "missing=1"), v)
	if got {
		t.Errorf("an unknown group must yield false, got true")
	}
	var uge *UnknownGroupError
	if !errors.As(err, &uge) {
		t.Fatalf("expected *UnknownGroupError, got %T (%v)", err, err)
	}
	if uge.Group != "missing" {
		t.Errorf("UnknownGroupError.Group = %q, expected \"missing\"", uge.Group)
	}
}

func TestEval_UnknownGroup_ShortCircuitsFalse(t *testing.T) {
	// The first atom is false, so the overall result is false without accessing
	// the unknown group.
	v := Values{"database": "mysql"}
	got, err := Eval(cond(t, "database=postgres && missing=1"), v)
	if got || err != nil {
		t.Errorf("expected (false, nil), got (%v, %v)", got, err)
	}
}

func TestEvalAny_OR(t *testing.T) {
	v := Values{"brokers": []string{"kafka"}}
	conds := []manifest.Condition{
		cond(t, "brokers=rabbitmq"),
		cond(t, "brokers=kafka"),
	}
	got, err := EvalAny(conds, v)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !got {
		t.Errorf("EvalAny should be true (kafka present)")
	}

	none, _ := EvalAny([]manifest.Condition{cond(t, "brokers=nats")}, v)
	if none {
		t.Errorf("EvalAny should be false")
	}

	empty, _ := EvalAny(nil, v)
	if empty {
		t.Errorf("empty condition list -> false")
	}
}

func TestEvalAny_CollectsWarnings(t *testing.T) {
	v := Values{"brokers": []string{"kafka"}}
	conds := []manifest.Condition{
		cond(t, "missing=1"),
		cond(t, "brokers=kafka"),
	}
	got, err := EvalAny(conds, v)
	if !got {
		t.Errorf("should be true (second condition is true)")
	}
	if err == nil {
		t.Errorf("warning about unknown group should be returned even with true")
	}
}
