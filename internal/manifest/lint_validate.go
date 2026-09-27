package manifest

import (
	"fmt"
	"sort"
	"strings"
)

// checkLint валидирует opt-in секцию lint (реализация проверку): ID правила известен,
// paths непустые и являются корректными глобами, exclude (если задан) —
// корректные глобы. Секция необязательна — пустой/нулевой LintConfig не
// добавляет проблем.
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

// sortedLintRuleIDs возвращает известные ID правил в детерминированном порядке
// (для сообщений валидатора).
func sortedLintRuleIDs() []string {
	ids := make([]string, 0, len(knownLintRuleIDs))
	for id := range knownLintRuleIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
