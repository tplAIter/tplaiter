package engine

import (
	"fmt"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// compileFileRules builds the set of file globs excluded from the render set
// by the manifest's files rules:
//
//	render set = all tree files MINUS (paths rules with a false condition)
//	                                 MINUS (remove rules with a true condition)
//
// Thus paths means “include when true” (when false, the path is excluded as if
// it did not exist); remove means “remove when true” (composite removal — the
// equivalent of the COMPOSITE_REMOVALS Python hook).
//
// A rule condition is exactly one of When ([manifest.ParseCondition] plus
// [settings.Eval]) or AnyOf (a list of conditions with OR semantics through
// [settings.EvalAny]); a rule with neither field is a no-op (the manifest
// validator rejects such rules; this layer simply ignores them).
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

// evalFileRule evaluates one files-rule condition. An unknown group in the
// condition is a manifest authoring error (it aborts Render), rather than a
// silent false: files rules define the tree contents, so silently ignoring an
// error would produce an incomplete project without notice.
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
