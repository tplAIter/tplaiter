package engine

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestTruthy(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"bool true", true, true},
		{"bool false", false, false},
		{"string non-empty", "postgres", true},
		{"string empty", "", false},
		{"slice non-empty", []string{"kafka"}, true},
		{"slice empty", []string{}, false},
		{"slice nil", []string(nil), false},
		{"int non-zero", 4, true},
		{"int zero", 0, false},
		{"unsupported type", 3.14, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := truthy(c.v); got != c.want {
				t.Errorf("truthy(%#v) = %v, want %v", c.v, got, c.want)
			}
		})
	}
}

func TestEvalIfSegmentNotConditional(t *testing.T) {
	values := settings.Values{"database": "postgres"}
	for _, seg := range []string{"internal", "db.go", "__if_", "__if_x", "if_database__", "__slug__"} {
		_, ok, err := evalIfSegment(seg, values)
		if err != nil {
			t.Fatalf("evalIfSegment(%q) unexpected error: %v", seg, err)
		}
		if ok {
			t.Errorf("evalIfSegment(%q) ok = true, want false (not a conditional segment)", seg)
		}
	}
}

func TestEvalIfSegmentGenericTruthiness(t *testing.T) {
	values := settings.Values{
		"database": "none",
		"brokers":  []string{"kafka"},
		"empty":    []string{},
		"active":   true,
		"inactive": false,
	}
	cases := []struct {
		seg  string
		want bool
	}{
		{"__if_database__", true}, // select "none" != zero-value "" — истинно (см. описание поведения)
		{"__if_brokers__", true},
		{"__if_empty__", false},
		{"__if_active__", true},
		{"__if_inactive__", false},
	}
	for _, c := range cases {
		active, ok, err := evalIfSegment(c.seg, values)
		if err != nil {
			t.Fatalf("evalIfSegment(%q): %v", c.seg, err)
		}
		if !ok {
			t.Fatalf("evalIfSegment(%q) ok = false, want true", c.seg)
		}
		if active != c.want {
			t.Errorf("evalIfSegment(%q) = %v, want %v", c.seg, active, c.want)
		}
	}
}

func TestEvalIfSegmentAtomForm(t *testing.T) {
	values := settings.Values{
		"database": "postgres",
		"brokers":  []string{"kafka"},
	}
	cases := []struct {
		seg  string
		want bool
	}{
		{"__if_database=postgres__", true},
		{"__if_database=mysql__", false},
		{"__if_brokers=kafka__", true},
		{"__if_brokers=rabbitmq__", false},
	}
	for _, c := range cases {
		active, ok, err := evalIfSegment(c.seg, values)
		if err != nil {
			t.Fatalf("evalIfSegment(%q): %v", c.seg, err)
		}
		if !ok {
			t.Fatalf("evalIfSegment(%q) ok = false, want true", c.seg)
		}
		if active != c.want {
			t.Errorf("evalIfSegment(%q) = %v, want %v", c.seg, active, c.want)
		}
	}
}

func TestEvalIfSegmentUnknownGroup(t *testing.T) {
	values := settings.Values{"database": "postgres"}

	if _, ok, err := evalIfSegment("__if_nope__", values); !ok || err == nil {
		t.Errorf("evalIfSegment(__if_nope__) = ok=%v err=%v, want ok=true, err!=nil", ok, err)
	}
	if _, ok, err := evalIfSegment("__if_nope=x__", values); !ok || err == nil {
		t.Errorf("evalIfSegment(__if_nope=x__) = ok=%v err=%v, want ok=true, err!=nil", ok, err)
	}
}

func TestEvalIfSegmentMalformedAtom(t *testing.T) {
	values := settings.Values{"database": "postgres"}
	_, ok, err := evalIfSegment("__if_database=__", values)
	if !ok {
		t.Fatalf("expected ok=true for a segment recognisable as conditional")
	}
	if err == nil {
		t.Error("expected error for malformed atom (empty value)")
	}
}
