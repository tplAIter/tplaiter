package inittemplate

import (
	"sort"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Combo — одна «угловая» комбинация настроек для lint-template.
// Explicit — набор ЯВНО задаваемых значений (как из --set); транзитивное
// довключение requires и активацию вложенных групп выполняет [settings.Resolve].
type Combo struct {
	// Name — человекочитаемое имя комбинации: `defaults`, `<group>=<opt>`,
	// `all-on`, `max`.
	Name string
	// Explicit — явные значения групп (id → значение канонического типа).
	Explicit settings.Values
}

// groupOpts — select/multiselect-группа с её не-planned опциями.
type groupOpts struct {
	group string
	opts  []string
}

// Combos строит набор «угловых» комбинаций настроек манифеста,
// generic по любому дереву групп:
//
//   - defaults — пустой набор (все дефолты);
//   - для каждой select-группы × каждая её не-planned опция — `<group>=<opt>`;
//   - для каждой multiselect-группы × каждая её не-planned опция — `<group>=<opt>`
//     (одиночный выбор — угловой случай проверки `has`);
//   - all-on — все toggle разом true;
//   - max — все toggle true + все multiselect выбраны целиком + каждая select
//     переключена на последнюю не-planned опцию (максимальная активация
//     вложенных уточнений).
//
// Обход дерева включает вложенные группы (Option.Settings). Комбинации
// дедуплицируются по имени; сами значения дальше разрешает [settings.Resolve]
// (он же дотягивает requires и обнуляет неактивные вложенные группы).
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

// nonPlannedOptions возвращает id опций группы, кроме служебных planned
// (невыбираемых — , честность каталога).
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

// dedupeByName убирает повторы по имени, сохраняя первый порядок появления.
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

// FilterCombos оставляет комбинации с именем name (точное совпадение). Пустое
// name — без фильтра. Возвращает отфильтрованный список и множество известных
// имён (для сообщения об ошибке вызывающему).
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

// satisfyConstraints до-выполняет constraints комбо (fixpoint): если `if`
// выполняется на полных значениях, а `require` — нет, атомы require добавляются
// в explicit. Иначе generic-комбо вида all-on (все toggle=true) падали бы на
// манифестах с инвариантами «toggle требует select-значение» (находка :
// idempotency ⇒ database=postgres в go-template).
func satisfyConstraints(tpl *manifest.Template, explicit settings.Values) settings.Values {
	out := explicit.Clone()
	// Верхняя граница итераций — по числу constraints (каждая может сработать раз).
	for range len(tpl.Constraints) + 1 {
		full := settings.DefaultValues(tpl)
		for k, v := range out {
			full[k] = v
		}
		changed := false
		for _, c := range tpl.Constraints {
			condIf, err := manifest.ParseCondition(c.If)
			if err != nil {
				continue // битые условия ловит Validate
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
					continue // require с != не «довключается» — оставляем Resolve
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

// coerceAtomValue приводит строковое значение атома к типу группы.
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

// flattenGroups — плоский список всех групп дерева (включая вложенные).
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
