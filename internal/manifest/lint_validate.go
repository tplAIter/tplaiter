package manifest

import (
	"fmt"
	"sort"
	"strings"
)

// checkLint validates the opt-in lint section (the  check): the rule ID is
// known, paths are non-empty valid globs, and exclude (when set) contains valid
// globs. The section is optional; an empty or nil LintConfig adds no problems.
func (v *validator) checkLint(l LintConfig) {
	for i := range l.Rules {
		r := &l.Rules[i]
		loc := fmt.Sprintf("lint.rules[%d]", i)

		if r.ID == "" {
			v.add(loc+".id", "id правила обязателен")
		} else if !knownLintRuleIDs[r.ID] {
			v.add(loc+".id", "неизвестный id правила %q (известны: %s)", r.ID, strings.Join(sortedLintRuleIDs(), "|"))
		}

		if len(r.Paths) == 0 {
			v.add(loc+".paths", "правило без paths ничего не проверяет")
		}
		v.checkGlobs(loc+".paths", r.Paths)
		v.checkGlobs(loc+".exclude", r.Exclude)
	}
}

// sortedLintRuleIDs returns known rule IDs in deterministic order (for
// validator messages).
func sortedLintRuleIDs() []string {
	ids := make([]string, 0, len(knownLintRuleIDs))
	for id := range knownLintRuleIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
