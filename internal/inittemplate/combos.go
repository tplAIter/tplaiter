package inittemplate

import (
	"sort"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Combo — one corner-case settings combination for lint-template.
// Explicit is the set of EXPLICIT values (as from --set); [settings.Resolve]
// performs transitive requires and nested-group activation.
type Combo struct {
	// Name — human-readable combination name: `defaults`, `<group>=<opt>`,
	// `all-on`, `max`.
	Name string
	// Explicit — explicit group values (ID → canonical-type value).
	Explicit settings.Values
}

// groupOpts — select/multiselect group with its non-planned options.
type groupOpts struct {
	group string
	opts  []string
}

// Combos builds corner-case manifest-setting combinations, generic over any group tree:
//
//   - defaults — empty set (all defaults);
//   - each select group × each non-planned option — `<group>=<opt>`;
//   - each multiselect group × each non-planned option — `<group>=<opt>`
//     (single selection is the corner case for checking `has`);
//   - all-on — every toggle true;
//   - max — every toggle true + every multiselect fully selected + each select
//     switched to its last non-planned option (maximum nested activation).
//
// Tree traversal includes nested groups (Option.Settings). Combinations are
// deduplicated by name; [settings.Resolve] resolves values later (also pulling
// requires and clearing inactive nested groups).
func Combos(tpl *manifest.Template) []Combo {
	var selects, multis []groupOpts
	var toggles []string

	var walk func(groups []manifest.SettingGroup)
	walk = func(groups []manifest.SettingGroup) {
		for i := range groups {
			g := &groups[i]
			switch g.Type {
			case manifest.TypeSelect:
				selects = append(selects, groupOpts{group: g.Group, opts: nonPlannedOptions(g)})
			case manifest.TypeMultiselect:
				multis = append(multis, groupOpts{group: g.Group, opts: nonPlannedOptions(g)})
			case manifest.TypeToggle:
				toggles = append(toggles, g.Group)
			}
			for j := range g.Options {
				walk(g.Options[j].Settings)
			}
		}
	}
	walk(tpl.Settings)

	combos := []Combo{{Name: "defaults", Explicit: settings.Values{}}}

	for _, s := range selects {
		for _, opt := range s.opts {
			combos = append(combos, Combo{
				Name:     s.group + manifest.OpEq + opt,
				Explicit: settings.Values{s.group: opt},
			})
		}
	}
	for _, ms := range multis {
		for _, opt := range ms.opts {
			combos = append(combos, Combo{
				Name:     ms.group + manifest.OpEq + opt,
				Explicit: settings.Values{ms.group: []string{opt}},
			})
		}
	}

	if len(toggles) > 0 {
		v := make(settings.Values, len(toggles))
		for _, t := range toggles {
			v[t] = true
		}
		combos = append(combos, Combo{Name: "all-on", Explicit: v})
	}

	maxVals := make(settings.Values)
	for _, t := range toggles {
		maxVals[t] = true
	}
	for _, ms := range multis {
		maxVals[ms.group] = append([]string{}, ms.opts...)
	}
	for _, s := range selects {
		if len(s.opts) > 0 {
			maxVals[s.group] = s.opts[len(s.opts)-1]
		}
	}
	if len(maxVals) > 0 {
		combos = append(combos, Combo{Name: "max", Explicit: maxVals})
	}

	for i := range combos {
		combos[i].Explicit = satisfyConstraints(tpl, combos[i].Explicit)
	}
	return dedupeByName(combos)
}

// nonPlannedOptions returns group option IDs except service planned options
// (non-selectable, for catalog integrity).
func nonPlannedOptions(g *manifest.SettingGroup) []string {
	out := make([]string, 0, len(g.Options))
	for i := range g.Options {
		if g.Options[i].Status == manifest.StatusPlanned {
			continue
		}
		out = append(out, g.Options[i].ID)
	}
	return out
}

// dedupeByName removes duplicate names while preserving first-seen order.
func dedupeByName(combos []Combo) []Combo {
	seen := make(map[string]bool, len(combos))
	out := combos[:0]
	for _, c := range combos {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, c)
	}
	return out
}

// FilterCombos keeps combinations with an exact name match. Empty name means no
// filter. Returns the filtered list and the set of known names for caller errors.
func FilterCombos(combos []Combo, name string) (filtered []Combo, known []string) {
	known = make([]string, 0, len(combos))
	for _, c := range combos {
		known = append(known, c.Name)
		if name == "" || c.Name == name {
			filtered = append(filtered, c)
		}
	}
	sort.Strings(known)
	return filtered, known
}

// satisfyConstraints completes combo constraints to a fixpoint: when `if` holds
// for full values but `require` does not, require atoms are added to explicit.
// Otherwise generic all-on combos (all toggles=true) would fail manifests with
// invariants such as "toggle requires a select value" (finding: idempotency ⇒
// database=postgres in go-template).
func satisfyConstraints(tpl *manifest.Template, explicit settings.Values) settings.Values {
	out := explicit.Clone()
	// Iteration upper bound is the number of constraints (each can fire once).
	for range len(tpl.Constraints) + 1 {
		full := settings.DefaultValues(tpl)
		for k, v := range out {
			full[k] = v
		}
		changed := false
		for _, c := range tpl.Constraints {
			condIf, err := manifest.ParseCondition(c.If)
			if err != nil {
				continue // Validate catches malformed conditions
			}
			ok, err := settings.Eval(condIf, full)
			if err != nil || !ok {
				continue
			}
			condReq, err := manifest.ParseCondition(c.Require)
			if err != nil {
				continue
			}
			if ok, _ := settings.Eval(condReq, full); ok {
				continue
			}
			for _, atom := range condReq.Atoms {
				if atom.Op != manifest.OpEq {
					continue // require with != is not auto-enabled — leave it to Resolve
				}
				out[atom.Group] = coerceAtomValue(tpl, atom.Group, atom.Value)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return out
}

// coerceAtomValue converts an atom's string value to the group's type.
func coerceAtomValue(tpl *manifest.Template, group, value string) any {
	for _, g := range flattenGroups(tpl.Settings) {
		if g.Group != group {
			continue
		}
		switch g.Type {
		case manifest.TypeToggle:
			return value == "true"
		case manifest.TypeMultiselect:
			return []string{value}
		case manifest.TypeInt:
			if n, err := strconv.Atoi(value); err == nil {
				return n
			}
		}
		return value
	}
	return value
}

// flattenGroups — flat list of all groups in the tree (including nested groups).
func flattenGroups(groups []manifest.SettingGroup) []manifest.SettingGroup {
	out := make([]manifest.SettingGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, g)
		for _, opt := range g.Options {
			out = append(out, flattenGroups(opt.Settings)...)
		}
	}
	return out
}
