package settingscmd

import (
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func surveyReanswer(view *NativeView, group string, d Deps) ([]string, error) {
	if !updateplan.SettingsGroupActive(view.Template, view.Values, group) {
		return nil, fmt.Errorf("%w: inactive group %q", updateplan.ErrSettingsInput, group)
	}
	var selected []manifest.SettingGroup
	var find func([]manifest.SettingGroup)
	find = func(groups []manifest.SettingGroup) {
		for _, g := range groups {
			if g.Group == group {
				selected = []manifest.SettingGroup{g}
				return
			}
			for _, o := range g.Options {
				find(o.Settings)
			}
		}
	}
	find(view.Template.Settings)
	current := view.Values.Clone()
	for {
		asked, err := d.Prompter.Ask(selected, current)
		if err != nil {
			return nil, err
		}
		var pairs []string
		activeValues := current.Clone()
		for key, value := range asked {
			activeValues[key] = value
		}
		walkGroups(selected, activeValues, true, 0, func(g *manifest.SettingGroup, active bool, _ int) {
			if active {
				if value, ok := asked[g.Group]; ok {
					pairs = append(pairs, g.Group+"="+settingTransport(value))
				}
			}
		})
		resolved, err := updateplan.ResolveSettingsAnswers(view.Template, view.Answers, pairs)
		if err != nil {
			return nil, err
		}
		printSettingsTable(d.Out, d.Palette, view.Template, resolved.Values)
		yes, err := d.Prompter.Confirm("Apply authenticated settings plan?")
		if err != nil {
			return nil, err
		}
		if yes {
			return pairs, nil
		}
		current = resolved.Values
	}
}

func settingTransport(value any) string {
	if list, ok := value.([]string); ok {
		return strings.Join(list, ",")
	}
	return fmt.Sprint(value)
}

// PrintNativeView renders only the already authenticated settings facts.
func PrintNativeView(d Deps, v *NativeView) {
	printSettingsTable(d.Out, d.Palette, v.Template, v.Values)
}
