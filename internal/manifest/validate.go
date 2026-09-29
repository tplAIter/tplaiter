package manifest

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Issue is one validation problem. Path is a logical address within the manifest
// (for example, `settings[0].options[1].id`), more stable than a line number
// when YAML is reformatted.
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

// ValidationErrors is an aggregate list of manifest validation problems. All
// problems are collected in one pass and returned together.
type ValidationErrors []Issue

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "manifest is valid"
	}
	parts := make([]string, len(e))
	for i, issue := range e {
		parts[i] = issue.String()
	}
	return fmt.Sprintf("manifest is invalid (%d problems):\n  - %s", len(e), strings.Join(parts, "\n  - "))
}

var (
	slugRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	groupRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	optionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	// paramNameRe is a generator parameter name (a CLI flag): a letter followed
	// by letters, digits, or a hyphen (kebab case, e.g. with-list).
	paramNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
)

// groupInfo contains group data for condition reference checks.
type groupInfo struct {
	typ     string
	options map[string]bool // option id -> planned?
}

// condRef is a condition with its declaration location for deferred reference checks.
type condRef struct {
	loc  string
	expr string
}

type validator struct {
	issues []Issue
	groups map[string]groupInfo
	conds  []condRef
}

// Validate checks a template manifest. It returns nil when there are no problems,
// otherwise [ValidationErrors] with all discovered problems.
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
	v.checkLint(t.Lint) // checks the opt-in architecture-lint section; see lint_validate.go

	// Check condition references after fully building the group map because a
	// condition may refer to a group declared later or deeper in the tree.
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
		v.add("metadata.name", "template name is required")
	} else if !slugRe.MatchString(t.Metadata.Name) {
		v.add("metadata.name", "name %q is not in slug format (lowercase letters/digits separated by hyphens)", t.Metadata.Name)
	}
	if t.Metadata.Version == "" {
		v.add("metadata.version", "template version is required")
	} else if !semverRe.MatchString(t.Metadata.Version) {
		v.add("metadata.version", "version %q is not a valid SemVer", t.Metadata.Version)
	}
}

// walkGroups recursively traverses the settings tree, registering groups and
// options and collecting conditions (Option.Requires) for deferred checking.
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
		v.add(loc+".group", "group id is required")
	case !groupRe.MatchString(g.Group):
		v.add(loc+".group", "group id %q is invalid (letters/digits/underscore, must start with a letter)", g.Group)
	default:
		if _, dup := v.groups[g.Group]; dup {
			v.add(loc+".group", "duplicate group id %q (ids must be globally unique, including nested)", g.Group)
		}
	}

	if !isKnownType(g.Type) {
		v.add(loc+".type", "unknown type %q (select|multiselect|toggle|string|int)", g.Type)
	}

	optionIDs := v.checkOptions(g, loc)
	v.checkDefault(g, loc, optionIDs)

	// Register the group (first occurrence) for reference checks.
	if g.Group != "" {
		if _, exists := v.groups[g.Group]; !exists {
			v.groups[g.Group] = groupInfo{typ: g.Type, options: optionIDs}
		}
	}

	// Recurse into nested refinement groups.
	for i := range g.Options {
		opt := &g.Options[i]
		optLoc := fmt.Sprintf("%s.options[%d]", loc, i)
		for j, req := range opt.Requires {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.requires[%d]", optLoc, j), expr: req})
		}
		v.walkGroups(opt.Settings, optLoc+".settings")
	}
}

// checkOptions validates group options and returns the id -> planned set.
func (v *validator) checkOptions(g *SettingGroup, loc string) map[string]bool {
	ids := make(map[string]bool)
	needsOptions := g.Type == TypeSelect || g.Type == TypeMultiselect

	if !needsOptions {
		if len(g.Options) > 0 {
			v.add(loc+".options", "type %q does not support options", g.Type)
		}
		return ids
	}
	if len(g.Options) == 0 {
		v.add(loc+".options", "type %q requires a non-empty options list", g.Type)
		return ids
	}

	for i := range g.Options {
		opt := &g.Options[i]
		optLoc := fmt.Sprintf("%s.options[%d]", loc, i)
		switch {
		case opt.ID == "":
			v.add(optLoc+".id", "option id is required")
		case !optionRe.MatchString(opt.ID):
			v.add(optLoc+".id", "option id %q is invalid", opt.ID)
		default:
			if _, dup := ids[opt.ID]; dup {
				v.add(optLoc+".id", "duplicate option id %q in group %q", opt.ID, g.Group)
			} else {
				ids[opt.ID] = opt.Status == StatusPlanned
			}
		}
		if opt.Status != "" && opt.Status != StatusPlanned {
			v.add(optLoc+".status", "invalid status %q (empty|planned)", opt.Status)
		}
	}
	return ids
}

// checkDefault matches default against the group type and, for select/multiselect,
// against the option set; a planned option cannot be the default value.
func (v *validator) checkDefault(g *SettingGroup, loc string, optionIDs map[string]bool) {
	if g.Default == nil {
		return
	}
	dloc := loc + ".default"
	switch g.Type {
	case TypeSelect:
		s, ok := g.Default.(string)
		if !ok {
			v.add(dloc, "default for select must be a string (option id)")
			return
		}
		v.checkOptionValue(dloc, g.Group, s, optionIDs)
	case TypeMultiselect:
		list, ok := g.Default.([]any)
		if !ok {
			v.add(dloc, "default for multiselect must be a list of option ids")
			return
		}
		for _, el := range list {
			s, ok := el.(string)
			if !ok {
				v.add(dloc, "default element %v is not a string", el)
				continue
			}
			v.checkOptionValue(dloc, g.Group, s, optionIDs)
		}
	case TypeToggle:
		if _, ok := g.Default.(bool); !ok {
			v.add(dloc, "default for toggle must be bool")
		}
	case TypeString:
		if _, ok := g.Default.(string); !ok {
			v.add(dloc, "default for string must be a string")
		}
	case TypeInt:
		if _, ok := g.Default.(int); !ok {
			v.add(dloc, "default for int must be an integer")
		}
	}
}

func (v *validator) checkOptionValue(loc, group, value string, optionIDs map[string]bool) {
	planned, ok := optionIDs[value]
	if !ok {
		v.add(loc, "default value %q not found among options of group %q", value, group)
		return
	}
	if planned {
		v.add(loc, "planned option %q cannot be a default value", value)
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
			v.add(loc, "when and anyOf are set simultaneously — leave only one")
		case !hasWhen && !hasAnyOf:
			v.add(loc, "rule without when/anyOf has no condition")
		}
		if len(f.Paths) == 0 && len(f.Remove) == 0 {
			v.add(loc, "rule without paths and remove does nothing")
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
			v.add(fmt.Sprintf("%s[%d]", loc, i), "invalid glob %q: %v", g, err)
		}
	}
}

func (v *validator) checkEngineGlobs(e Engine) {
	v.checkGlobs("engine.copyWithoutRender", e.CopyWithoutRender)
	for i := range e.PostReplace {
		if _, err := path.Match(e.PostReplace[i].Glob, ""); err != nil {
			v.add(fmt.Sprintf("engine.postReplace[%d].glob", i), "invalid glob %q: %v", e.PostReplace[i].Glob, err)
		}
	}
}

func (v *validator) checkConstraints(cs []Constraint) {
	for i := range cs {
		loc := fmt.Sprintf("constraints[%d]", i)
		if cs[i].If == "" {
			v.add(loc+".if", "if condition is required")
		} else {
			v.conds = append(v.conds, condRef{loc: loc + ".if", expr: cs[i].If})
		}
		if cs[i].Require == "" {
			v.add(loc+".require", "require condition is required")
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
	sort.Strings(names) // deterministic issue order
	for _, name := range names {
		c := cmds[name]
		loc := fmt.Sprintf("commands[%q]", name)
		if strings.TrimSpace(c.Run) == "" {
			v.add(loc+".run", "command must specify a non-empty run")
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
			v.add(loc+".kind", "generator kind is required")
		}
		v.checkGeneratorForm(g, loc)
		v.checkGeneratorParams(g, loc)
		for j, w := range g.When {
			v.conds = append(v.conds, condRef{loc: fmt.Sprintf("%s.when[%d]", loc, j), expr: w})
		}
	}
}

// checkGeneratorForm validates mutual exclusion of single-file (snippet+target)
// and multi-file (targets[]) generator forms: exactly one must be specified.
func (v *validator) checkGeneratorForm(g *Generator, loc string) {
	hasSingle := strings.TrimSpace(g.Snippet) != "" || strings.TrimSpace(g.Target) != ""
	hasMulti := len(g.Targets) > 0

	switch {
	case hasSingle && hasMulti:
		v.add(loc, "both single-file form (snippet/target) and multi-file form (targets) are specified — leave only one")
	case hasMulti:
		v.checkTargets(g.Targets, loc)
	default:
		// Single-file form (or an empty generator): both fields are required.
		if strings.TrimSpace(g.Snippet) == "" {
			v.add(loc+".snippet", "generator snippet is required (or use targets[])")
		}
		if strings.TrimSpace(g.Target) == "" {
			v.add(loc+".target", "generator target is required (or use targets[])")
		}
	}
}

func (v *validator) checkTargets(targets []Target, loc string) {
	for i := range targets {
		t := &targets[i]
		tloc := fmt.Sprintf("%s.targets[%d]", loc, i)
		if strings.TrimSpace(t.Snippet) == "" {
			v.add(tloc+".snippet", "target snippet is required")
		}
		if strings.TrimSpace(t.Target) == "" {
			v.add(tloc+".target", "target path is required")
		}
		if t.Numbered != "" && t.Numbered != NumberedGoose {
			v.add(tloc+".numbered", "unknown numbering strategy %q (empty|%s)", t.Numbered, NumberedGoose)
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
			v.add(ploc+".name", "parameter name is required")
		case !paramNameRe.MatchString(p.Name):
			v.add(ploc+".name", "invalid parameter name %q (letters/digits/hyphen, must start with a letter)", p.Name)
		case seen[p.Name]:
			v.add(ploc+".name", "duplicate parameter name %q", p.Name)
		default:
			seen[p.Name] = true
		}
		if !isKnownParamType(p.Type) {
			v.add(ploc+".type", "unknown parameter type %q (%s|%s|%s|%s|%s)",
				p.Type, ParamTypeString, ParamTypeBool, ParamTypeInt, ParamTypeFields, ParamTypeList)
		}
		if p.Pattern != "" {
			if p.Type != ParamTypeString && p.Type != ParamTypeInt {
				v.add(ploc+".pattern", "pattern is only supported for string or int parameters, not %q", p.Type)
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				v.add(ploc+".pattern", "invalid regexp %q: %v", p.Pattern, err)
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

// checkConditionRefs validates syntax of every collected condition and the
// reference integrity of its atoms against the group map.
func (v *validator) checkConditionRefs() {
	for _, c := range v.conds {
		cond, err := ParseCondition(c.expr)
		if err != nil {
			v.add(c.loc, "condition %q: %v", c.expr, err)
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
		v.add(loc, "condition references non-existent group %q", atom.Group)
		return
	}
	switch info.typ {
	case TypeSelect, TypeMultiselect:
		if _, ok := info.options[atom.Value]; !ok {
			v.add(loc, "group %q does not have option %q", atom.Group, atom.Value)
		}
	case TypeToggle:
		if atom.Value != "true" && atom.Value != "false" {
			v.add(loc, "toggle group %q is compared with %q (expected true|false)", atom.Group, atom.Value)
		}
	case TypeInt:
		if _, err := strconv.Atoi(atom.Value); err != nil {
			v.add(loc, "int group %q is compared with non-numeric %q", atom.Group, atom.Value)
		}
	case TypeString:
		// The value is arbitrary, so there is nothing to validate.
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
