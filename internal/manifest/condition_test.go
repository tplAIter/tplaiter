package manifest

import (
	"errors"
	"testing"
)

func TestParseCondition_OK(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Atom
	}{
		{
			name: "single eq",
			in:   "database=postgres",
			want: []Atom{{Group: "database", Op: OpEq, Value: "postgres"}},
		},
		{
			name: "single neq",
			in:   "brokers!=kafka",
			want: []Atom{{Group: "brokers", Op: OpNeq, Value: "kafka"}},
		},
		{
			name: "toggle bool",
			in:   "idempotency=true",
			want: []Atom{{Group: "idempotency", Op: OpEq, Value: "true"}},
		},
		{
			name: "conjunction",
			in:   "database=postgres && brokers=kafka",
			want: []Atom{
				{Group: "database", Op: OpEq, Value: "postgres"},
				{Group: "brokers", Op: OpEq, Value: "kafka"},
			},
		},
		{
			name: "spaces tolerated",
			in:   "  database   =   postgres  &&brokers!=rabbitmq ",
			want: []Atom{
				{Group: "database", Op: OpEq, Value: "postgres"},
				{Group: "brokers", Op: OpNeq, Value: "rabbitmq"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCondition(tc.in)
			if err != nil {
				t.Fatalf("ParseCondition(%q) вернул ошибку: %v", tc.in, err)
			}
			if len(got.Atoms) != len(tc.want) {
				t.Fatalf("atoms = %v, want %v", got.Atoms, tc.want)
			}
			for i, a := range got.Atoms {
				if a != tc.want[i] {
					t.Errorf("atom[%d] = %+v, want %+v", i, a, tc.want[i])
				}
			}
		})
	}
}

func TestParseCondition_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"no operator", "database"},
		{"empty group", "=postgres"},
		{"empty value", "database="},
		{"empty atom in conjunction", "database=postgres &&"},
		{"double operator in value", "database==postgres"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCondition(tc.in); err == nil {
				t.Fatalf("ParseCondition(%q) ожидалась ошибка, got nil", tc.in)
			}
		})
	}
}

func TestParseCondition_EmptyIsSentinel(t *testing.T) {
	_, err := ParseCondition("")
	if !errors.Is(err, ErrEmptyCondition) {
		t.Fatalf("err = %v, want ErrEmptyCondition", err)
	}
}

func TestCondition_String(t *testing.T) {
	c, err := ParseCondition("database=postgres && brokers!=kafka")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.String(), "database=postgres && brokers!=kafka"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
