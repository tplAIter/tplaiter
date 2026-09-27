package engine

import (
	"fmt"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// compileFileRules строит набор глобов файлов, исключаемых из рендер-набора
// правилами files манифеста:
//
//	render-набор = все файлы дерева MINUS (paths правил с ложным условием)
//	                                 MINUS (remove правил с истинным условием)
//
// То есть paths — «включить при true» (полноценность: при false путь
// исключается, будто его не было); remove — «удалить при true» (composite
// removal — , аналог COMPOSITE_REMOVALS python-хука).
//
// Условие правила — ровно одно из When ([manifest.ParseCondition] +
// [settings.Eval]) или AnyOf (список условий, семантика OR через
// [settings.EvalAny]); правило без обоих полей — no-op (валидатор манифеста,
// реализация , такие правила отклоняет — здесь просто игнорируется).
func compileFileRules(rules []manifest.FileRule, values settings.Values) (*globSet, error) {
	var excluded []string
	for i := range rules {
		rule := &rules[i]
		ok, err := evalFileRule(rule, values)
		if err != nil {
			return nil, fmt.Errorf("engine: files[%d]: %w", i, err)
		}
		if !ok {
			excluded = append(excluded, rule.Paths...)
		} else {
			excluded = append(excluded, rule.Remove...)
		}
	}
	return newGlobSet(excluded), nil
}

// evalFileRule вычисляет условие одного правила files. Неизвестная группа в
// условии — ошибка автора манифеста (прерывает Render), а не молчаливое false:
// files-правила определяют состав дерева, тихая ошибка здесь означала бы
// незаметно неполный проект.
func evalFileRule(rule *manifest.FileRule, values settings.Values) (bool, error) {
	switch {
	case rule.When != "":
		cond, err := manifest.ParseCondition(rule.When)
		if err != nil {
			return false, fmt.Errorf("when %q: %w", rule.When, err)
		}
		ok, err := settings.Eval(cond, values)
		if err != nil {
			return false, fmt.Errorf("when %q: %w", rule.When, err)
		}
		return ok, nil
	case len(rule.AnyOf) > 0:
		conds := make([]manifest.Condition, 0, len(rule.AnyOf))
		for _, expr := range rule.AnyOf {
			cond, err := manifest.ParseCondition(expr)
			if err != nil {
				return false, fmt.Errorf("anyOf %q: %w", expr, err)
			}
			conds = append(conds, cond)
		}
		ok, err := settings.EvalAny(conds, values)
		if err != nil {
			return false, fmt.Errorf("anyOf %v: %w", rule.AnyOf, err)
		}
		return ok, nil
	default:
		return false, nil
	}
}
