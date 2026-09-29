package manifest

import (
	"errors"
	"fmt"
	"strings"
)

// Condition atom operators.
const (
	OpEq  = "="
	OpNeq = "!="
)

// ErrEmptyCondition is returned by [ParseCondition] for an empty condition string.
var ErrEmptyCondition = errors.New("empty condition")

// Atom is an elementary `group=value` or `group!=value` comparison (for a
// multiselect, `=` means contains and `!=` means does not contain); a toggle is
// compared with `true`/`false`. The resolver implements evaluation semantics;
// this package only defines structure and syntax.
type Atom struct {
	Group string
	Op    string // OpEq | OpNeq
	Value string
}

// String returns the canonical atom representation (`group=value`).
func (a Atom) String() string { return a.Group + a.Op + a.Value }

// Condition is a conjunction of atoms joined by `&&`. Disjunction is expressed
// as a list of conditions in the calling field (`when: [a, b]`); OR is not
// supported inside one string to preserve determinism.
type Condition struct {
	Atoms []Atom
}

// String returns the canonical condition form (atoms joined by ` && `).
func (c Condition) String() string {
	parts := make([]string, len(c.Atoms))
	for i, a := range c.Atoms {
		parts[i] = a.String()
	}
	return strings.Join(parts, " && ")
}

// Groups returns group names referenced by the condition in occurrence order,
// including duplicates; callers deduplicate them if needed.
func (c Condition) Groups() []string {
	groups := make([]string, 0, len(c.Atoms))
	for _, a := range c.Atoms {
		groups = append(groups, a.Group)
	}
	return groups
}

// ParseCondition parses a §3.2 condition string. It returns [ErrEmptyCondition]
// for an empty string and a descriptive syntax error otherwise. The validator
// separately checks semantics (the existence of groups and values).
func ParseCondition(s string) (Condition, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return Condition{}, ErrEmptyCondition
	}

	rawAtoms := strings.Split(trimmed, "&&")
	atoms := make([]Atom, 0, len(rawAtoms))
	for _, raw := range rawAtoms {
		atom, err := parseAtom(raw)
		if err != nil {
			return Condition{}, err
		}
		atoms = append(atoms, atom)
	}
	return Condition{Atoms: atoms}, nil
}

// parseAtom parses one atom. It checks `!=` before `=`, otherwise `!=` would be
// incorrectly split at `=` with an empty operator.
func parseAtom(raw string) (Atom, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Atom{}, fmt.Errorf("empty atom in condition %q", raw)
	}

	op := OpEq
	idx := strings.Index(s, OpNeq)
	if idx >= 0 {
		op = OpNeq
	} else {
		idx = strings.Index(s, OpEq)
	}
	if idx < 0 {
		return Atom{}, fmt.Errorf("atom %q has no operator = or !=", s)
	}

	group := strings.TrimSpace(s[:idx])
	value := strings.TrimSpace(s[idx+len(op):])
	if group == "" {
		return Atom{}, fmt.Errorf("atom %q has no group name", s)
	}
	if value == "" {
		return Atom{}, fmt.Errorf("atom %q has no value", s)
	}
	if strings.ContainsAny(group, "=!&") {
		return Atom{}, fmt.Errorf("invalid character in group name of atom %q", s)
	}
	if strings.Contains(value, OpEq) || strings.Contains(value, "!") {
		return Atom{}, fmt.Errorf("extra operator in value of atom %q", s)
	}
	return Atom{Group: group, Op: op, Value: value}, nil
}
