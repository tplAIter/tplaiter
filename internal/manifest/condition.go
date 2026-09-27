package manifest

import (
	"errors"
	"fmt"
	"strings"
)

// Операторы атома условия.
const (
	OpEq  = "="
	OpNeq = "!="
)

// ErrEmptyCondition возвращается [ParseCondition] для пустой строки условия.
var ErrEmptyCondition = errors.New("пустое условие")

// Atom — элементарное сравнение `group=value` или `group!=value` (для
// multiselect `=` означает «содержит», `!=` — «не содержит»); toggle
// сравнивается с `true`/`false`. Семантику вычисления реализует резолвер
// (реализация ); здесь только структура и синтаксис.
type Atom struct {
	Group string
	Op    string // OpEq | OpNeq
	Value string
}

// String возвращает канонический вид атома (`group=value`).
func (a Atom) String() string { return a.Group + a.Op + a.Value }

// Condition — конъюнкция атомов через `&&`. Дизъюнкции
// выражаются списком условий на уровне вызывающего поля (`when: [a, b]`),
// внутри одной строки OR не поддерживается — детерминизм важнее.
type Condition struct {
	Atoms []Atom
}

// String возвращает канонический вид условия (атомы через ` && `).
func (c Condition) String() string {
	parts := make([]string, len(c.Atoms))
	for i, a := range c.Atoms {
		parts[i] = a.String()
	}
	return strings.Join(parts, " && ")
}

// Groups возвращает имена групп, на которые ссылается условие (в порядке
// появления, с повторами — вызывающий дедуплицирует при необходимости).
func (c Condition) Groups() []string {
	groups := make([]string, 0, len(c.Atoms))
	for _, a := range c.Atoms {
		groups = append(groups, a.Group)
	}
	return groups
}

// ParseCondition разбирает строку условия §3.2. Возвращает [ErrEmptyCondition]
// для пустой строки и содержательную ошибку синтаксиса иначе. Семантика
// (существование групп/значений) проверяется валидатором отдельно.
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

// parseAtom разбирает один атом. `!=` проверяется раньше `=`, иначе `!=` был бы
// ошибочно разрезан по `=` с пустым оператором.
func parseAtom(raw string) (Atom, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Atom{}, fmt.Errorf("пустой атом в условии %q", raw)
	}

	op := OpEq
	idx := strings.Index(s, OpNeq)
	if idx >= 0 {
		op = OpNeq
	} else {
		idx = strings.Index(s, OpEq)
	}
	if idx < 0 {
		return Atom{}, fmt.Errorf("атом %q без оператора = или !=", s)
	}

	group := strings.TrimSpace(s[:idx])
	value := strings.TrimSpace(s[idx+len(op):])
	if group == "" {
		return Atom{}, fmt.Errorf("атом %q без имени группы", s)
	}
	if value == "" {
		return Atom{}, fmt.Errorf("атом %q без значения", s)
	}
	if strings.ContainsAny(group, "=!&") {
		return Atom{}, fmt.Errorf("недопустимый символ в имени группы атома %q", s)
	}
	if strings.Contains(value, OpEq) || strings.Contains(value, "!") {
		return Atom{}, fmt.Errorf("лишний оператор в значении атома %q", s)
	}
	return Atom{Group: group, Op: op, Value: value}, nil
}
