package updateplan

import (
	"fmt"
	"reflect"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

// ResolveSettingsAnswers resolves operator intent against recorded answer origins.
// It is a pure calculation, never a source or publication authority. Default
// origins follow the signed manifest and requires; all other recorded origins
// remain explicit, including user answers equal to a default.
func ResolveSettingsAnswers(tpl *manifest.Template, before map[string]stateledger.Answer, pairs []string) (settings.Resolved, error) {
	explicit := settings.Values{}
	prior := settings.DefaultValues(tpl)
	for key, answer := range before {
		prior[key] = answer.Value
		switch answer.Source {
		case "default":
		case "user", "legacy", "migration":
			explicit[key] = answer.Value
		default:
			return settings.Resolved{}, fmt.Errorf("%w: invalid answer origin", ErrSettingsInput)
		}
	}
	resolved, err := resolveSettingsExplicit(tpl, renderref.Values(explicit), pairs, renderref.Values(prior))
	if err != nil {
		return settings.Resolved{}, err
	}
	// Inactive snapshots are historical recorded answers, not explicit choices
	// for active requires resolution. Restore them only after final ancestry is
	// known; active default origins still follow current defaults and requires.
	for key, answer := range before {
		if !SettingsGroupActive(tpl, resolved.Values, key) {
			resolved.Values[key] = renderref.Values(settings.Values{key: answer.Value})[key]
		}
	}
	// Validate the complete retained snapshot through the same resolver used by
	// rendering. This preserves constraint checks without making recorded inactive
	// defaults explicit during the initial active requires calculation.
	snapshot, err := settings.Resolve(tpl, resolved.Values)
	if err != nil {
		return settings.Resolved{}, fmt.Errorf("%w: %w", ErrSettingsInput, err)
	}
	resolved.ActiveValues = snapshot.ActiveValues
	return resolved, nil
}

// SettingsGroupActive evaluates the full original manifest ancestry. Selecting
// a subtree must never make an inactive descendant appear to be a root.
func SettingsGroupActive(tpl *manifest.Template, values settings.Values, group string) bool {
	var active bool
	var walk func([]manifest.SettingGroup, bool)
	walk = func(groups []manifest.SettingGroup, parentActive bool) {
		for _, g := range groups {
			if g.Group == group {
				active = parentActive
			}
			for _, option := range g.Options {
				selected := false
				switch value := values[g.Group].(type) {
				case string:
					selected = value == option.ID
				case []string:
					for _, item := range value {
						if item == option.ID {
							selected = true
						}
					}
				}
				walk(option.Settings, parentActive && selected)
			}
		}
	}
	walk(tpl.Settings, true)
	return active
}

func settingsAnswerAfterimages(tpl *manifest.Template, before map[string]stateledger.Answer, values settings.Values, pairs []string) (map[string]stateledger.Answer, error) {
	submitted := map[string]bool{}
	for _, pair := range pairs {
		key, _, err := settings.ParseSet(tpl, pair)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSettingsInput, err)
		}
		submitted[key] = true
	}
	out := make(map[string]stateledger.Answer, len(before))
	for key, answer := range before {
		out[key] = answer
	}
	for key, value := range values {
		answer, exists := before[key]
		if exists && !submitted[key] && !SettingsGroupActive(tpl, values, key) {
			continue // The copied recorded value and origin remain exact while inactive.
		}
		if !exists {
			answer.Source = "default"
		}
		if submitted[key] {
			answer.Source = "user"
		}
		answer.Value = value
		out[key] = answer
	}
	return out, nil
}

func settingsAnswersEqual(a, b map[string]stateledger.Answer) bool {
	normalize := func(in map[string]stateledger.Answer) map[string]stateledger.Answer {
		out := make(map[string]stateledger.Answer, len(in))
		for key, answer := range in {
			answer.Value = renderref.Values(settings.Values{key: answer.Value})[key]
			out[key] = answer
		}
		return out
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}
