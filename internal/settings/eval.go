package settings

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// UnknownGroupError сообщает, что условие ссылается на группу, отсутствующую в
// наборе значений. Не паника: атом с неизвестной группой вычисляется как false,
// а ошибка возвращается отдельно как предупреждение вызывающему.
type UnknownGroupError struct {
	Group string
}

func (e *UnknownGroupError) Error() string {
	return fmt.Sprintf("условие ссылается на неизвестную группу %q", e.Group)
}

// Eval вычисляет условие §3.2 на наборе значений: конъюнкция всех атомов.
// Семантика атома определяется рантайм-типом значения группы:
//   - bool (toggle): сравнение с "true"/"false";
//   - []string (multiselect): "=" — содержит, "!=" — не содержит;
//   - int: числовое сравнение;
//   - string (select/string): равенство.
//
// Неизвестная группа даёт false и возвращается как [*UnknownGroupError]
// (первая встреченная). При ошибке результат гарантированно false.
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

// EvalAny вычисляет список условий по семантике OR (`when: [a, b]` в §3.2):
// true, если истинно хотя бы одно. Предупреждения о неизвестных группах
// собираются со всех условий и возвращаются объединённой ошибкой (даже если
// итог true), чтобы вызывающий мог их залогировать.
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

// evalAtom вычисляет один атом. Тип сравнения выводится из рантайм-типа
// значения; операторный `!=` инвертирует результат совпадения.
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

// matchValue сопоставляет значение группы со строковым операндом атома с учётом
// рантайм-типа значения.
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

// joinWarnings объединяет несколько предупреждений в одно (nil, если их нет).
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
