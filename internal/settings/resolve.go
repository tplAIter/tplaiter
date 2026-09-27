package settings

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ImpliedValue — значение, довключённое резолвером транзитивно через requires
// (пользователь его явно не задавал). RequiredBy — id опции, потребовавшей это
// значение.
type ImpliedValue struct {
	Group      string `yaml:"group" json:"group"`
	Value      string `yaml:"value" json:"value"`
	RequiredBy string `yaml:"requiredBy" json:"requiredBy"`
}

// Report — доклад резолвера пользователю: что было довключено и какие
// предупреждения возникли (неактивные группы со сброшенными значениями и т.п.).
type Report struct {
	Implied  []ImpliedValue `yaml:"implied" json:"implied"`
	Warnings []string       `yaml:"warnings" json:"warnings"`
}

// Resolved — результат разрешения настроек.
//
//   - Values — полный набор значений (дефолты + explicit + довключённые
//     requires) для ВСЕХ групп, включая неактивные вложенные. Сохраняется в
//     .tplaiter/project.yaml как снимок для update/переопроса.
//   - ActiveValues — производное представление для рендера: неактивные вложенные
//     группы (родительская опция не выбрана) сброшены в zero-значение своего
//     типа. Это устраняет протечки вида «kafka_ssl=true при brokers без kafka»:
//     контекст движка видит kafka_ssl=false, хотя снимок хранит заданное true.
type Resolved struct {
	Values       Values
	ActiveValues Values
	Report       Report
}

// ConflictError — requires опции противоречит явно заданному значению группы
// (для select/toggle/int/string перезапись explicit-значения запрещена).
type ConflictError struct {
	RequiredBy  string   // id опции, потребовавшей значение
	Requirement string   // канонический атом требования (group=value)
	Group       string   // группа с конфликтующим значением
	Current     string   // текущее (явно заданное) значение группы
	Chain       []string // цепочка ключей опций до конфликта
}

func (e *ConflictError) Error() string {
	msg := fmt.Sprintf("%s требует %s, но задано %s=%s", e.RequiredBy, e.Requirement, e.Group, e.Current)
	if len(e.Chain) > 1 {
		msg += " (цепочка: " + strings.Join(e.Chain, " → ") + ")"
	}
	return msg
}

// CycleError — цикл в графе requires (опция A требует B, B требует … A).
type CycleError struct {
	Chain []string
}

func (e *CycleError) Error() string {
	return "цикл в requires: " + strings.Join(e.Chain, " → ")
}

// ConstraintError — нарушен межгрупповой инвариант constraints (§3): if
// выполнен, а require — нет.
type ConstraintError struct {
	If      string
	Require string
	Message string
}

func (e *ConstraintError) Error() string { return e.Message }

// resolver держит рабочее состояние одного вызова [Resolve].
type resolver struct {
	tpl      *manifest.Template
	gidx     map[string]groupMeta
	oidx     map[string]optionMeta
	values   Values
	explicit map[string]bool
	implied  []ImpliedValue
	warnings []string

	onStack map[string]bool
	done    map[string]bool
}

// Resolve — ядро модели настроек. Начинает с [DefaultValues],
// накладывает explicit-значения, транзитивно дотягивает requires выбранных
// опций (довключение с докладом или конфликт-ошибка), детектит циклы requires,
// проверяет constraints и строит ActiveValues. Возвращает [Resolved] либо
// типизированную ошибку ([*ConflictError]/[*CycleError]/[*ConstraintError]).
func Resolve(tpl *manifest.Template, explicit Values) (Resolved, error) {
	r := &resolver{
		tpl:      tpl,
		gidx:     indexGroups(tpl),
		oidx:     indexOptions(tpl),
		values:   DefaultValues(tpl),
		explicit: make(map[string]bool),
		onStack:  make(map[string]bool),
		done:     make(map[string]bool),
	}

	r.overlayExplicit(explicit)

	if err := r.resolveRequires(); err != nil {
		return Resolved{}, err
	}
	if err := r.checkConstraints(); err != nil {
		return Resolved{}, err
	}

	active := r.activeValues()

	sort.Slice(r.implied, func(i, j int) bool {
		if r.implied[i].Group != r.implied[j].Group {
			return r.implied[i].Group < r.implied[j].Group
		}
		return r.implied[i].Value < r.implied[j].Value
	})
	sort.Strings(r.warnings)

	return Resolved{
		Values:       r.values,
		ActiveValues: active,
		Report:       Report{Implied: r.implied, Warnings: r.warnings},
	}, nil
}

// overlayExplicit накладывает заданные значения поверх дефолтов, помечая группы
// как явно заданные. Неизвестные группы игнорируются с предупреждением.
func (r *resolver) overlayExplicit(explicit Values) {
	keys := make([]string, 0, len(explicit))
	for k := range explicit {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := r.gidx[k]; !ok {
			r.warn("неизвестная группа %q в заданных значениях — игнорируется", k)
			continue
		}
		r.values[k] = explicit[k]
		r.explicit[k] = true
	}
}

// resolveRequires разрешает requires до неподвижной точки: на каждом проходе
// обходит выбранные опции активных групп; активированные довключением группы
// подхватываются следующим проходом. Транзитивность внутри прохода — рекурсией
// [resolver.visit].
func (r *resolver) resolveRequires() error {
	for {
		progressed := false
		for _, key := range r.activeSelectedKeys() {
			if r.done[key] {
				continue
			}
			if err := r.visit(key, nil); err != nil {
				return err
			}
			progressed = true
		}
		if !progressed {
			return nil
		}
	}
}

// visit обрабатывает requires одной выбранной опции, рекурсивно спускаясь в
// довключённые опции. Возврат в опцию, уже находящуюся в стеке обработки, —
// цикл requires.
func (r *resolver) visit(key string, stack []string) error {
	if r.onStack[key] {
		return &CycleError{Chain: append(append([]string{}, stack...), key)}
	}
	if r.done[key] {
		return nil
	}
	om, ok := r.oidx[key]
	if !ok {
		// Ключ ссылается на не-опцию (toggle/int/string) — обходить нечего.
		r.done[key] = true
		return nil
	}

	r.onStack[key] = true
	stack = append(stack, key)

	for _, reqExpr := range om.opt.Requires {
		cond, err := manifest.ParseCondition(reqExpr)
		if err != nil {
			return fmt.Errorf("опция %q: неразбираемое требование %q: %w", key, reqExpr, err)
		}
		for _, atom := range cond.Atoms {
			nextKey, err := r.ensure(atom, om.opt.ID, stack)
			if err != nil {
				return err
			}
			if nextKey != "" {
				if err := r.visit(nextKey, stack); err != nil {
					return err
				}
			}
		}
	}

	r.onStack[key] = false
	r.done[key] = true
	return nil
}

// ensure добивается выполнения одного requires-атома. Возвращает ключ
// "group=value" опции для дальнейшего обхода (для select/multiselect `=`, в т.ч.
// уже выполненных — чтобы детектить структурные циклы) либо "". Конфликт с
// explicit-значением или невыполнимый негатив → типизированная ошибка.
func (r *resolver) ensure(a manifest.Atom, requiredBy string, stack []string) (string, error) {
	m, ok := r.gidx[a.Group]
	if !ok {
		r.warn("требование опции %q ссылается на неизвестную группу %q — пропущено", requiredBy, a.Group)
		return "", nil
	}
	holds := atomHolds(a, r.values)

	if a.Op == manifest.OpNeq {
		if !holds {
			return "", r.conflict(requiredBy, a, stack)
		}
		return "", nil
	}

	key := a.Group + manifest.OpEq + a.Value
	switch m.g.Type {
	case manifest.TypeSelect:
		if holds {
			return key, nil
		}
		if r.explicit[a.Group] {
			return "", r.conflict(requiredBy, a, stack)
		}
		if !r.isOption(key) {
			return "", fmt.Errorf("опция %q требует несуществующую опцию %s", requiredBy, key)
		}
		r.values[a.Group] = a.Value
		r.imply(a.Group, a.Value, requiredBy)
		return key, nil
	case manifest.TypeMultiselect:
		if holds {
			return key, nil
		}
		if !r.isOption(key) {
			return "", fmt.Errorf("опция %q требует несуществующую опцию %s", requiredBy, key)
		}
		list := asStringSlice(r.values[a.Group])
		r.values[a.Group] = append(list, a.Value)
		r.imply(a.Group, a.Value, requiredBy)
		return key, nil
	case manifest.TypeToggle:
		if holds {
			return "", nil
		}
		if r.explicit[a.Group] {
			return "", r.conflict(requiredBy, a, stack)
		}
		r.values[a.Group] = a.Value == "true"
		r.imply(a.Group, a.Value, requiredBy)
		return "", nil
	case manifest.TypeInt:
		if holds {
			return "", nil
		}
		if r.explicit[a.Group] {
			return "", r.conflict(requiredBy, a, stack)
		}
		n, err := strconv.Atoi(a.Value)
		if err != nil {
			return "", fmt.Errorf("опция %q требует нечисловое значение %s", requiredBy, key)
		}
		r.values[a.Group] = n
		r.imply(a.Group, a.Value, requiredBy)
		return "", nil
	default: // string
		if holds {
			return "", nil
		}
		if r.explicit[a.Group] {
			return "", r.conflict(requiredBy, a, stack)
		}
		r.values[a.Group] = a.Value
		r.imply(a.Group, a.Value, requiredBy)
		return "", nil
	}
}

func (r *resolver) conflict(requiredBy string, a manifest.Atom, stack []string) error {
	return &ConflictError{
		RequiredBy:  requiredBy,
		Requirement: a.String(),
		Group:       a.Group,
		Current:     formatValue(r.values[a.Group]),
		Chain:       append([]string{}, stack...),
	}
}

func (r *resolver) imply(group, value, requiredBy string) {
	r.implied = append(r.implied, ImpliedValue{Group: group, Value: value, RequiredBy: requiredBy})
}

func (r *resolver) warn(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func (r *resolver) isOption(key string) bool {
	_, ok := r.oidx[key]
	return ok
}

// checkConstraints проверяет межгрупповые инварианты на полном наборе значений
// (не ActiveValues — чтобы ловить рассогласование вида idempotency=true при
// database=none). Возвращает первое нарушение.
func (r *resolver) checkConstraints() error {
	for i := range r.tpl.Constraints {
		c := r.tpl.Constraints[i]
		ifCond, err := manifest.ParseCondition(c.If)
		if err != nil {
			return fmt.Errorf("constraints[%d].if: %w", i, err)
		}
		reqCond, err := manifest.ParseCondition(c.Require)
		if err != nil {
			return fmt.Errorf("constraints[%d].require: %w", i, err)
		}
		ifOK, _ := Eval(ifCond, r.values)
		if !ifOK {
			continue
		}
		reqOK, _ := Eval(reqCond, r.values)
		if reqOK {
			continue
		}
		msg := c.Message
		if msg == "" {
			msg = fmt.Sprintf("нарушено ограничение: если %s, требуется %s", c.If, c.Require)
		}
		return &ConstraintError{If: c.If, Require: c.Require, Message: msg}
	}
	return nil
}

// activeValues строит производный набор для рендера: неактивные группы сброшены
// в zero своего типа. Если у сброшенной группы было непустое значение —
// добавляется предупреждение.
func (r *resolver) activeValues() Values {
	active := r.values.Clone()
	// Детерминированный порядок предупреждений — обход по отсортированным id.
	ids := make([]string, 0, len(r.gidx))
	for id := range r.gidx {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if r.isActive(id) {
			continue
		}
		m := r.gidx[id]
		// Предупреждаем только если сбрасывается ОСМЫСЛЕННО заданное значение
		// (отличное от дефолта группы) — иначе неактивная группа с ненулевым
		// дефолтом (напр. pg_shards=4) шумела бы предупреждением на ровном месте.
		if !equalValue(active[id], defaultFor(m.g)) {
			r.warn("группа %q неактивна (родительская опция не выбрана) — значение сброшено в контексте рендера", id)
		}
		active[id] = zeroValue(m.g.Type)
	}
	return active
}

// isActive сообщает, активна ли группа: корневые активны всегда, вложенная —
// когда активен родитель и в нём выбрана активирующая опция.
func (r *resolver) isActive(id string) bool {
	m, ok := r.gidx[id]
	if !ok {
		return false
	}
	if m.parentGroup == "" {
		return true
	}
	if !r.isActive(m.parentGroup) {
		return false
	}
	return r.optionSelected(m.parentGroup, m.parentOpt)
}

// optionSelected сообщает, выбрана ли опция opt в группе group.
func (r *resolver) optionSelected(group, opt string) bool {
	switch val := r.values[group].(type) {
	case string:
		return val == opt
	case []string:
		return contains(val, opt)
	default:
		return false
	}
}

// activeSelectedKeys возвращает ключи "group=option" выбранных опций активных
// select/multiselect-групп в порядке объявления (детерминизм).
func (r *resolver) activeSelectedKeys() []string {
	var keys []string
	var walk func(groups []manifest.SettingGroup)
	walk = func(groups []manifest.SettingGroup) {
		for i := range groups {
			g := &groups[i]
			if (g.Type == manifest.TypeSelect || g.Type == manifest.TypeMultiselect) && r.isActive(g.Group) {
				for _, val := range r.selectedValues(g) {
					keys = append(keys, g.Group+manifest.OpEq+val)
				}
			}
			for j := range g.Options {
				walk(g.Options[j].Settings)
			}
		}
	}
	walk(r.tpl.Settings)
	return keys
}

// selectedValues возвращает выбранные значения группы (для select — одно, для
// multiselect — список), только реально существующие опции.
func (r *resolver) selectedValues(g *manifest.SettingGroup) []string {
	switch val := r.values[g.Group].(type) {
	case string:
		if val != "" && r.isOption(g.Group+manifest.OpEq+val) {
			return []string{val}
		}
	case []string:
		out := make([]string, 0, len(val))
		for _, s := range val {
			if r.isOption(g.Group + manifest.OpEq + s) {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// atomHolds сообщает, выполняется ли атом на значениях (группа гарантированно
// присутствует у вызывающего).
func atomHolds(a manifest.Atom, v Values) bool {
	match := matchValue(v[a.Group], a.Value)
	if a.Op == manifest.OpNeq {
		return !match
	}
	return match
}

// asStringSlice возвращает []string-значение группы (копию не делает — вызов
// сразу append'ит новый элемент, что создаёт новый backing-массив при нехватке
// ёмкости; для безопасности копируем).
func asStringSlice(v any) []string {
	if list, ok := v.([]string); ok {
		cp := make([]string, len(list))
		copy(cp, list)
		return cp
	}
	return nil
}

// equalValue сравнивает значения настроек с поддержкой []string.
func equalValue(a, b any) bool {
	if av, ok := a.([]string); ok {
		bv, ok := b.([]string)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	}
	return a == b
}

// formatValue форматирует значение группы для сообщений об ошибках.
func formatValue(v any) string {
	if list, ok := v.([]string); ok {
		return strings.Join(list, ",")
	}
	return fmt.Sprintf("%v", v)
}
