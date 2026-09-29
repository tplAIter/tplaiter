package settings

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// UnknownGroupError reports that a condition refers to a group absent from the
// value set. This is not a panic: an atom with an unknown group evaluates to
// false and the error is separately returned to the caller as a warning.
type UnknownGroupError struct {
	Group string
}

func (e *UnknownGroupError) Error() string {
	return fmt.Sprintf("condition refers to unknown group %q", e.Group)
}

// Eval evaluates a §3.2 condition on a value set: a conjunction of all atoms.
// Atom semantics are determined by the runtime type of the group value:
//   - bool (toggle): comparison with "true"/"false";
//   - []string (multiselect): "=" means contains and "!=" means does not contain;
//   - int: numeric comparison;
//   - string (select/string): equality.
//
// An unknown group produces false and is returned as the first encountered
// [*UnknownGroupError]. When there is an error, the result is always false.
func Eval(cond manifest.Condition, v Values) (bool, error) {
	var warn error
	for _, atom := range cond.Atoms {
		ok, err := evalAtom(atom, v)
		if err != nil {
			if warn == nil {
				warn = err
			}
			return false, warn
		}
		if !ok {
			return false, nil
		}
	}
	return true, warn
}

// EvalAny evaluates a condition list with OR semantics (`when: [a, b]` in §3.2):
// true if at least one is true. Unknown-group warnings from all conditions are
// collected and returned as a combined error (even if the result is true), so
// the caller can log them.
func EvalAny(conds []manifest.Condition, v Values) (bool, error) {
	if len(conds) == 0 {
		return false, nil
	}
	var warns []error
	result := false
	for _, cond := range conds {
		ok, err := Eval(cond, v)
		if err != nil {
			warns = append(warns, err)
		}
		if ok {
			result = true
		}
	}
	return result, joinWarnings(warns)
}

// evalAtom evaluates one atom. The comparison type follows the runtime value
// type; the `!=` operator inverts the match result.
func evalAtom(a manifest.Atom, v Values) (bool, error) {
	raw, ok := v[a.Group]
	if !ok {
		return false, &UnknownGroupError{Group: a.Group}
	}
	match := matchValue(raw, a.Value)
	if a.Op == manifest.OpNeq {
		return !match, nil
	}
	return match, nil
}

// matchValue matches a group value against an atom's string operand, respecting
// the runtime type of the value.
func matchValue(raw any, value string) bool {
	switch val := raw.(type) {
	case bool:
		return val == (value == "true")
	case []string:
		return contains(val, value)
	case int:
		n, err := strconv.Atoi(value)
		if err != nil {
			return false
		}
		return val == n
	case string:
		return val == value
	default:
		return false
	}
}

// joinWarnings combines several warnings into one (nil when there are none).
func joinWarnings(warns []error) error {
	switch len(warns) {
	case 0:
		return nil
	case 1:
		return warns[0]
	default:
		msgs := make([]string, len(warns))
		for i, w := range warns {
			msgs[i] = w.Error()
		}
		return errors.New(strings.Join(msgs, "; "))
	}
}
