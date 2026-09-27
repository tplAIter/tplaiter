package settings

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ImpliedValue is a value transitively added by the resolver through requires
// (the user did not set it explicitly). RequiredBy is the id of the option that
// required this value.
type ImpliedValue struct {
	Group      string `yaml:"group" json:"group"`
	Value      string `yaml:"value" json:"value"`
	RequiredBy string `yaml:"requiredBy" json:"requiredBy"`
}

// Report is the resolver report to the user: what it implied and what warnings
// occurred (inactive groups with reset values, and so on).
type Report struct {
	Implied  []ImpliedValue `yaml:"implied" json:"implied"`
	Warnings []string       `yaml:"warnings" json:"warnings"`
}

// Resolved is the settings resolution result.
//
//   - Values is the complete value set (defaults + explicit + implied requires)
//     for ALL groups, including inactive nested ones. It is stored in
//     .tplaiter/project.yaml as a snapshot for update/re-questioning.
//   - ActiveValues is the derived rendering view: inactive nested groups (whose
//     parent option is unselected) are reset to their type's zero value. This
//     prevents leaks such as kafka_ssl=true when brokers lacks kafka: the engine
//     context sees kafka_ssl=false even though the snapshot stores true.
type Resolved struct {
	Values       Values
	ActiveValues Values
	Report       Report
}

// ConflictError means an option's requires conflicts with an explicitly set group
// value (overwriting an explicit select/toggle/int/string value is forbidden).
type ConflictError struct {
	RequiredBy  string   // id of the option that required the value
	Requirement string   // canonical requirement atom (group=value)
	Group       string   // group with the conflicting value
	Current     string   // current explicitly set group value
	Chain       []string // option-key chain to the conflict
}

func (e *ConflictError) Error() string {
	msg := fmt.Sprintf("%s требует %s, но задано %s=%s", e.RequiredBy, e.Requirement, e.Group, e.Current)
	if len(e.Chain) > 1 {
		msg += " (цепочка: " + strings.Join(e.Chain, " → ") + ")"
	}
	return msg
}

// CycleError is a cycle in the requires graph (option A requires B, B requires … A).
type CycleError struct {
	Chain []string
}

func (e *CycleError) Error() string {
	return "цикл в requires: " + strings.Join(e.Chain, " → ")
}

// ConstraintError means a cross-group constraints invariant (§3) is violated:
// if holds but require does not.
type ConstraintError struct {
	If      string
	Require string
	Message string
}

func (e *ConstraintError) Error() string { return e.Message }

// resolver holds the working state of one [Resolve] call.
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

// Resolve is the core of the settings model. It starts with [DefaultValues],
// overlays explicit values, transitively satisfies requires of selected options
// (reporting implications or conflicts), detects requires cycles, checks
// constraints, and builds ActiveValues. It returns [Resolved] or a typed error
// ([*ConflictError]/[*CycleError]/[*ConstraintError]).
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

// overlayExplicit overlays supplied values on defaults, marking groups as
// explicitly set. Unknown groups are ignored with a warning.
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

// resolveRequires resolves requires to a fixed point: on every pass it traverses
// selected options of active groups; groups activated by implication are picked up
// by the next pass. Transitivity within a pass is recursive.
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

// visit processes requires of one selected option, recursively descending into
// implied options. Returning to an option already on the processing stack is a
// requires cycle.
func (r *resolver) visit(key string, stack []string) error {
	if r.onStack[key] {
		return &CycleError{Chain: append(append([]string{}, stack...), key)}
	}
	if r.done[key] {
		return nil
	}
	om, ok := r.oidx[key]
	if !ok {
		// The key refers to a non-option (toggle/int/string), so there is nothing to traverse.
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

// ensure satisfies one requires atom. It returns the option's "group=value" key
// for further traversal (for select/multiselect `=`, including already satisfied
// atoms to detect structural cycles), or "". A conflict with an explicit value or
// an unsatisfiable negative produces a typed error.
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

// checkConstraints validates cross-group invariants on the complete value set,
// rather than ActiveValues, to catch inconsistencies such as idempotency=true
// with database=none. It returns the first violation.
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

// activeValues builds a derived rendering set: inactive groups are reset to their
// type's zero value. A warning is added if a reset group had a non-empty value.
func (r *resolver) activeValues() Values {
	active := r.values.Clone()
	// Deterministic warning order comes from traversal by sorted ids.
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
		// Warn only when a meaningfully set value (different from the group default)
		// is reset; otherwise an inactive group with a nonzero default (such as
		// pg_shards=4) would create a gratuitous warning.
		if !equalValue(active[id], defaultFor(m.g)) {
			r.warn("группа %q неактивна (родительская опция не выбрана) — значение сброшено в контексте рендера", id)
		}
		active[id] = zeroValue(m.g.Type)
	}
	return active
}

// isActive reports whether a group is active: roots are always active, and a
// nested group is active when its parent is active and its activating option is selected.
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

// optionSelected reports whether option opt is selected in group.
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

// activeSelectedKeys returns "group=option" keys of selected options in active
// select/multiselect groups in declaration order for determinism.
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

// selectedValues returns selected group values (one for select, a list for
// multiselect), limited to options that actually exist.
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

// atomHolds reports whether an atom holds on values; the caller guarantees the
// group is present.
func atomHolds(a manifest.Atom, v Values) bool {
	match := matchValue(v[a.Group], a.Value)
	if a.Op == manifest.OpNeq {
		return !match
	}
	return match
}

// asStringSlice returns a group's []string value. It does not copy because the
// caller immediately appends a new item, which allocates a new backing array when
// capacity is insufficient; copy it here for safety.
func asStringSlice(v any) []string {
	if list, ok := v.([]string); ok {
		cp := make([]string, len(list))
		copy(cp, list)
		return cp
	}
	return nil
}

// equalValue compares settings values with []string support.
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

// formatValue formats a group value for error messages.
func formatValue(v any) string {
	if list, ok := v.([]string); ok {
		return strings.Join(list, ",")
	}
	return fmt.Sprintf("%v", v)
}
