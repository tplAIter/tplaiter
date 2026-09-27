package manifest

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Issue — одна проблема валидации. Path — логический адрес внутри манифеста
// (например `settings[0].options[1].id`), стабильнее номера строки при
// переформатировании YAML.
type Issue struct {
	Path string
	Msg  string
}

func (i Issue) String() string {
	if i.Path == "" {
		return i.Msg
	}
	return i.Path + ": " + i.Msg
}

// ValidationErrors — агрегированный список проблем валидации манифеста. Все
// проблемы собираются за один проход и возвращаются вместе.
type ValidationErrors []Issue

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "манифест валиден"
	}
	parts := make([]string, len(e))
	for i, issue := range e {
		parts[i] = issue.String()
	}
	return fmt.Sprintf("манифест невалиден (%d проблем):\n  - %s", len(e), strings.Join(parts, "\n  - "))
}

var (
	slugRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	groupRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	optionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	// paramNameRe — имя параметра генератора (флаг CLI): буква, затем
	// буквы/цифры/дефис (kebab, напр. with-list).
	paramNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
)

// groupInfo — сведения о группе для проверки ссылок в условиях.
type groupInfo struct {
	typ     string
	options map[string]bool // id опции -> planned?
}

// condRef — условие с местом объявления для отложенной проверки ссылок.
type condRef struct {
	loc  string
	expr string
}

type validator struct {
	issues []Issue
	groups map[string]groupInfo
	conds  []condRef
}

// Validate проверяет манифест шаблона по  Возвращает nil, если
// проблем нет, иначе [ValidationErrors] со всеми найденными проблемами.
func (t *Template) Validate() error {
	v := &validator{groups: make(map[string]groupInfo)}

	v.checkMetadata(t)
	v.walkGroups(t.Settings, "settings")
	v.checkFiles(t.Files)
	v.checkConstraints(t.Constraints)
	v.checkCommands(t.Commands)
	v.checkGenerators(t.Generators)
	v.checkEngineGlobs(t.Engine)
	v.checkPlaybooks(t.Environment.Playbooks)
	v.checkLint(t.Lint) // проверку: opt-in arch-lint секция, см. lint_validate.go

	// Проверка ссылок в условиях — после полного построения карты групп,
	// т.к. условие может ссылаться на группу, объявленную позже/глубже.
	v.checkConditionRefs()

	if len(v.issues) == 0 {
		return nil
	}
	return ValidationErrors(v.issues)
}

func (v *validator) add(loc, format string, args ...any) {
	v.issues = append(v.issues, Issue{Path: loc, Msg: fmt.Sprintf(format, args...)})
}

func (v *validator) checkMetadata(t *Template) {
	if t.Metadata.Name == "" {
		v.add("metadata.name", "имя шаблона обязательно")
	} else if !slugRe.MatchString(t.Metadata.Name) {
		v.add("metadata.name", "имя %q не в формате slug (строчные буквы/цифры через дефис)", t.Metadata.Name)
	}
	if t.Metadata.Version == "" {
		v.add("metadata.version", "версия шаблона обязательна")
	} else if !semverRe.MatchString(t.Metadata.Version) {
		v.add("metadata.version", "версия %q не является SemVer", t.Metadata.Version)
	}
}

// walkGroups рекурсивно обходит дерево настроек, регистрируя группы и опции и
// собирая условия (Option.Requires) для отложенной проверки.
func (v *validator) walkGroups(groups []SettingGroup, prefix string) {
	for i := range groups {
		g := &groups[i]
		loc := fmt.Sprintf("%s[%d]", prefix, i)
		v.checkGroup(g, loc)
	}
}

func (v *validator) checkGroup(g *SettingGroup, loc string) {
	switch {
	case g.Group == "":
		v.add(loc+".group", "id группы обязателен")
	case !groupRe.MatchString(g.Group):
		v.add(loc+".group", "id группы %q недопустим (буквы/цифры/подчёркивание, начинается с буквы)", g.Group)
	default:
		if _, dup := v.groups[g.Group]; dup {
			v.add(loc+".group", "дублирующийся id группы %q (id глобально уникальны, включая вложенные)", g.Group)
		}
	}

	if !isKnownType(g.Type) {
		v.add(loc+".type", "неизвестный тип %q (select|multiselect|toggle|string|int)", g.Type)
	}

	optionIDs := v.checkOptions(g, loc)
	v.checkDefault(g, loc, optionIDs)

	// Регистрируем группу (первое вхождение) для проверки ссылок.
	if g.Group != "" {
		if _, exists := v.groups[g.Group]; !exists {
			v.groups[g.Group] = groupInfo{typ: g.Type, options: optionIDs}
		}
	}

	// Рекурсия во вложенные группы уточнений.
	for i := range g.Options {
		opt := &g.Options[i]
		optLoc := fmt.Sprintf("%s.options[%d]", loc, i)
		for j, req := range opt.Requires {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.requires[%d]", optLoc, j), expr: req})
		}
		v.walkGroups(opt.Settings, optLoc+".settings")
	}
}

// checkOptions проверяет опции группы и возвращает множество id -> planned.
func (v *validator) checkOptions(g *SettingGroup, loc string) map[string]bool {
	ids := make(map[string]bool)
	needsOptions := g.Type == TypeSelect || g.Type == TypeMultiselect

	if !needsOptions {
		if len(g.Options) > 0 {
			v.add(loc+".options", "тип %q не поддерживает options", g.Type)
		}
		return ids
	}
	if len(g.Options) == 0 {
		v.add(loc+".options", "тип %q требует непустой список options", g.Type)
		return ids
	}

	for i := range g.Options {
		opt := &g.Options[i]
		optLoc := fmt.Sprintf("%s.options[%d]", loc, i)
		switch {
		case opt.ID == "":
			v.add(optLoc+".id", "id опции обязателен")
		case !optionRe.MatchString(opt.ID):
			v.add(optLoc+".id", "id опции %q недопустим", opt.ID)
		default:
			if _, dup := ids[opt.ID]; dup {
				v.add(optLoc+".id", "дублирующийся id опции %q в группе %q", opt.ID, g.Group)
			} else {
				ids[opt.ID] = opt.Status == StatusPlanned
			}
		}
		if opt.Status != "" && opt.Status != StatusPlanned {
			v.add(optLoc+".status", "недопустимый status %q (пусто|planned)", opt.Status)
		}
	}
	return ids
}

// checkDefault сверяет default с типом группы и (для select/multiselect) с
// множеством опций; planned-опция не может быть значением по умолчанию.
func (v *validator) checkDefault(g *SettingGroup, loc string, optionIDs map[string]bool) {
	if g.Default == nil {
		return
	}
	dloc := loc + ".default"
	switch g.Type {
	case TypeSelect:
		s, ok := g.Default.(string)
		if !ok {
			v.add(dloc, "default для select должен быть строкой (id опции)")
			return
		}
		v.checkOptionValue(dloc, g.Group, s, optionIDs)
	case TypeMultiselect:
		list, ok := g.Default.([]any)
		if !ok {
			v.add(dloc, "default для multiselect должен быть списком id опций")
			return
		}
		for _, el := range list {
			s, ok := el.(string)
			if !ok {
				v.add(dloc, "элемент default %v не строка", el)
				continue
			}
			v.checkOptionValue(dloc, g.Group, s, optionIDs)
		}
	case TypeToggle:
		if _, ok := g.Default.(bool); !ok {
			v.add(dloc, "default для toggle должен быть bool")
		}
	case TypeString:
		if _, ok := g.Default.(string); !ok {
			v.add(dloc, "default для string должен быть строкой")
		}
	case TypeInt:
		if _, ok := g.Default.(int); !ok {
			v.add(dloc, "default для int должен быть целым числом")
		}
	}
}

func (v *validator) checkOptionValue(loc, group, value string, optionIDs map[string]bool) {
	planned, ok := optionIDs[value]
	if !ok {
		v.add(loc, "значение по умолчанию %q отсутствует среди опций группы %q", value, group)
		return
	}
	if planned {
		v.add(loc, "planned-опция %q не может быть значением по умолчанию", value)
	}
}

func (v *validator) checkFiles(files []FileRule) {
	for i := range files {
		f := &files[i]
		loc := fmt.Sprintf("files[%d]", i)
		hasWhen := f.When != ""
		hasAnyOf := len(f.AnyOf) > 0
		switch {
		case hasWhen && hasAnyOf:
			v.add(loc, "заданы одновременно when и anyOf — оставьте одно")
		case !hasWhen && !hasAnyOf:
			v.add(loc, "правило без when/anyOf не имеет условия")
		}
		if len(f.Paths) == 0 && len(f.Remove) == 0 {
			v.add(loc, "правило без paths и remove ничего не делает")
		}
		if hasWhen {
			v.conds = append(v.conds, condRef{loc: loc + ".when", expr: f.When})
		}
		for j, w := range f.AnyOf {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.anyOf[%d]", loc, j), expr: w})
		}
		v.checkGlobs(loc+".paths", f.Paths)
		v.checkGlobs(loc+".remove", f.Remove)
	}
}

func (v *validator) checkGlobs(loc string, globs []string) {
	for i, g := range globs {
		if _, err := path.Match(g, ""); err != nil {
			v.add(fmt.Sprintf("%s[%d]", loc, i), "некорректный glob %q: %v", g, err)
		}
	}
}

func (v *validator) checkEngineGlobs(e Engine) {
	v.checkGlobs("engine.copyWithoutRender", e.CopyWithoutRender)
	for i := range e.PostReplace {
		if _, err := path.Match(e.PostReplace[i].Glob, ""); err != nil {
			v.add(fmt.Sprintf("engine.postReplace[%d].glob", i), "некорректный glob %q: %v", e.PostReplace[i].Glob, err)
		}
	}
}

func (v *validator) checkConstraints(cs []Constraint) {
	for i := range cs {
		loc := fmt.Sprintf("constraints[%d]", i)
		if cs[i].If == "" {
			v.add(loc+".if", "условие if обязательно")
		} else {
			v.conds = append(v.conds, condRef{loc: loc + ".if", expr: cs[i].If})
		}
		if cs[i].Require == "" {
			v.add(loc+".require", "условие require обязательно")
		} else {
			v.conds = append(v.conds, condRef{loc: loc + ".require", expr: cs[i].Require})
		}
	}
}

func (v *validator) checkCommands(cmds map[string]Command) {
	names := make([]string, 0, len(cmds))
	for name := range cmds {
		names = append(names, name)
	}
	sort.Strings(names) // детерминированный порядок проблем
	for _, name := range names {
		c := cmds[name]
		loc := fmt.Sprintf("commands[%q]", name)
		if strings.TrimSpace(c.Run) == "" {
			v.add(loc+".run", "команда должна задавать непустой run")
		}
		if c.When != "" {
			v.conds = append(v.conds, condRef{loc: loc + ".when", expr: c.When})
		}
	}
}

func (v *validator) checkGenerators(gens []Generator) {
	for i := range gens {
		g := &gens[i]
		loc := fmt.Sprintf("generators[%d]", i)
		if g.Kind == "" {
			v.add(loc+".kind", "kind генератора обязателен")
		}
		v.checkGeneratorForm(g, loc)
		v.checkGeneratorParams(g, loc)
		for j, w := range g.When {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.when[%d]", loc, j), expr: w})
		}
	}
}

// checkGeneratorForm проверяет взаимоисключение одиночной (snippet+target) и
// мультифайловой (targets[]) форм генератора: ровно одна должна быть задана.
func (v *validator) checkGeneratorForm(g *Generator, loc string) {
	hasSingle := strings.TrimSpace(g.Snippet) != "" || strings.TrimSpace(g.Target) != ""
	hasMulti := len(g.Targets) > 0

	switch {
	case hasSingle && hasMulti:
		v.add(loc, "заданы одновременно одиночная форма (snippet/target) и мультифайловая (targets) — оставьте одну")
	case hasMulti:
		v.checkTargets(g.Targets, loc)
	default:
		// Одиночная форма (или пустой генератор): оба поля обязательны.
		if strings.TrimSpace(g.Snippet) == "" {
			v.add(loc+".snippet", "snippet генератора обязателен (или используйте targets[])")
		}
		if strings.TrimSpace(g.Target) == "" {
			v.add(loc+".target", "target генератора обязателен (или используйте targets[])")
		}
	}
}

func (v *validator) checkTargets(targets []Target, loc string) {
	for i := range targets {
		t := &targets[i]
		tloc := fmt.Sprintf("%s.targets[%d]", loc, i)
		if strings.TrimSpace(t.Snippet) == "" {
			v.add(tloc+".snippet", "snippet таргета обязателен")
		}
		if strings.TrimSpace(t.Target) == "" {
			v.add(tloc+".target", "target таргета обязателен")
		}
		if t.Numbered != "" && t.Numbered != NumberedGoose {
			v.add(tloc+".numbered", "неизвестная стратегия нумерации %q (пусто|%s)", t.Numbered, NumberedGoose)
		}
		for j, w := range t.When {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.when[%d]", tloc, j), expr: w})
		}
	}
}

func (v *validator) checkGeneratorParams(g *Generator, loc string) {
	seen := make(map[string]bool, len(g.Params))
	for i := range g.Params {
		p := &g.Params[i]
		ploc := fmt.Sprintf("%s.params[%d]", loc, i)
		switch {
		case p.Name == "":
			v.add(ploc+".name", "имя параметра обязательно")
		case !paramNameRe.MatchString(p.Name):
			v.add(ploc+".name", "недопустимое имя параметра %q (буквы/цифры/дефис, начинается с буквы)", p.Name)
		case seen[p.Name]:
			v.add(ploc+".name", "дублирующееся имя параметра %q", p.Name)
		default:
			seen[p.Name] = true
		}
		if !isKnownParamType(p.Type) {
			v.add(ploc+".type", "неизвестный тип параметра %q (%s|%s|%s|%s|%s)",
				p.Type, ParamTypeString, ParamTypeBool, ParamTypeInt, ParamTypeFields, ParamTypeList)
		}
		if p.Pattern != "" {
			if p.Type != ParamTypeString && p.Type != ParamTypeInt {
				v.add(ploc+".pattern", "pattern поддерживается только для параметров string или int, не %q", p.Type)
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				v.add(ploc+".pattern", "некорректный regexp %q: %v", p.Pattern, err)
			}
		}
	}
}

func isKnownParamType(t string) bool {
	switch t {
	case ParamTypeString, ParamTypeBool, ParamTypeInt, ParamTypeFields, ParamTypeList:
		return true
	default:
		return false
	}
}

func (v *validator) checkPlaybooks(pbs []Playbook) {
	for i := range pbs {
		if pbs[i].When != "" {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("environment.playbooks[%d].when", i), expr: pbs[i].When})
		}
	}
}

// checkConditionRefs проверяет синтаксис каждого собранного условия и ссылочную
// целостность его атомов относительно карты групп.
func (v *validator) checkConditionRefs() {
	for _, c := range v.conds {
		cond, err := ParseCondition(c.expr)
		if err != nil {
			v.add(c.loc, "условие %q: %v", c.expr, err)
			continue
		}
		for _, atom := range cond.Atoms {
			v.checkAtomRef(c.loc, atom)
		}
	}
}

func (v *validator) checkAtomRef(loc string, atom Atom) {
	info, ok := v.groups[atom.Group]
	if !ok {
		v.add(loc, "условие ссылается на несуществующую группу %q", atom.Group)
		return
	}
	switch info.typ {
	case TypeSelect, TypeMultiselect:
		if _, ok := info.options[atom.Value]; !ok {
			v.add(loc, "группа %q не имеет опции %q", atom.Group, atom.Value)
		}
	case TypeToggle:
		if atom.Value != "true" && atom.Value != "false" {
			v.add(loc, "toggle-группа %q сравнивается с %q (ожидается true|false)", atom.Group, atom.Value)
		}
	case TypeInt:
		if _, err := strconv.Atoi(atom.Value); err != nil {
			v.add(loc, "int-группа %q сравнивается с нечисловым %q", atom.Group, atom.Value)
		}
	case TypeString:
		// Значение произвольно — проверить нечего.
	}
}

func isKnownType(t string) bool {
	switch t {
	case TypeSelect, TypeMultiselect, TypeToggle, TypeString, TypeInt:
		return true
	default:
		return false
	}
}
