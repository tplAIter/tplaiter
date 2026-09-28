// Package survey implements an interactive template-settings questionnaire:
// it builds charmbracelet/huh forms from [manifest.SettingGroup] trees,
// orchestrates asking (AskFlow), and resolves results through [settings.Resolve]
// with implied-value reports and a value-source summary.
//
// The package builds on [settings] (values/resolver) and [manifest] (group-tree
// structure) without changing them. Testability is through [Prompter]:
// production [HuhPrompter] draws a TUI, while [ScriptedPrompter] replays answers without TTY.
package survey

import (
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Prompter abstracts settings input from questionnaire orchestration. Ask queries
// the supplied tree (already reduced to unset groups) from current values; Confirm
// shows a summary and asks for approval. Both return [huh.ErrUserAborted] on Ctrl+C,
// which the orchestrator propagates.
type Prompter interface {
	// Ask queries active groups in groups from current values and returns values
	// only for groups actually set (active).
	Ask(groups []manifest.SettingGroup, current settings.Values) (settings.Values, error)
	// Confirm shows summary and returns the user's approval.
	Confirm(summary string) (bool, error)
}

// Compile-time interface conformance checks.
var (
	_ Prompter = HuhPrompter{}
	_ Prompter = (*ScriptedPrompter)(nil)
)

// Source — source of a group's final value for the summary.
type Source string

// Possible sources of a setting value.
const (
	SourceSet     Source = "set"     // from --set
	SourceAnswer  Source = "answer"  // from --answers
	SourceDefault Source = "default" // manifest default
	SourcePrompt  Source = "prompt"  // entered in questionnaire
	SourceImplied Source = "implied" // implied by resolver
)

// ancestor — activating (group, option) pair on the path to a nested group.
type ancestor struct {
	group  string
	option string
}

// optionSelected reports whether optID is selected in a select/multiselect group
// for value val.
func optionSelected(typ string, val any, optID string) bool {
	switch typ {
	case manifest.TypeSelect:
		s, _ := val.(string)
		return s == optID
	case manifest.TypeMultiselect:
		list, _ := val.([]string)
		for _, s := range list {
			if s == optID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// selectedOptionIDs returns selected option IDs for val (at most one for select,
// a list for multiselect). It returns nil for non-option types.
func selectedOptionIDs(g *manifest.SettingGroup, val any) []string {
	switch g.Type {
	case manifest.TypeSelect:
		if s, ok := val.(string); ok && s != "" {
			return []string{s}
		}
	case manifest.TypeMultiselect:
		if list, ok := val.([]string); ok {
			return list
		}
	}
	return nil
}

// walkActive traverses groups in declaration order, calling fn for each ACTIVE
// group: roots are always active; nested groups are active when their parent's
// activating option is selected (value obtained through valueOf).
func walkActive(groups []manifest.SettingGroup, valueOf func(id string) any, fn func(g *manifest.SettingGroup)) {
	for i := range groups {
		g := &groups[i]
		fn(g)
		for j := range g.Options {
			opt := &g.Options[j]
			if optionSelected(g.Type, valueOf(g.Group), opt.ID) {
				walkActive(opt.Settings, valueOf, fn)
			}
		}
	}
}

// flattenTree traverses the ENTIRE tree regardless of selections (huh handles
// dynamics through WithHideFunc), passing each group and its activating-ancestor chain to fn.
func flattenTree(groups []manifest.SettingGroup, anc []ancestor, fn func(g *manifest.SettingGroup, anc []ancestor)) {
	for i := range groups {
		g := &groups[i]
		fn(g, anc)
		for j := range g.Options {
			opt := &g.Options[j]
			child := make([]ancestor, len(anc), len(anc)+1)
			copy(child, anc)
			child = append(child, ancestor{group: g.Group, option: opt.ID})
			flattenTree(opt.Settings, child, fn)
		}
	}
}

// pruneForPrompt returns the group subtree to ask interactively: preset-fixed
// groups (--set/--answers) are excluded, while active nested refinements of a
// selected preset option are promoted to the current level (their parent is fixed,
// so they are unconditionally active and need no WithHideFunc). Unset groups retain nesting.
func pruneForPrompt(groups []manifest.SettingGroup, preset settings.Values) []manifest.SettingGroup {
	out := make([]manifest.SettingGroup, 0, len(groups))
	for i := range groups {
		g := groups[i] // copy node (Options is replaced below)
		if presetVal, fixed := preset[g.Group]; fixed {
			for _, sel := range selectedOptionIDs(&g, presetVal) {
				for j := range g.Options {
					if g.Options[j].ID == sel {
						out = append(out, pruneForPrompt(g.Options[j].Settings, preset)...)
					}
				}
			}
			continue
		}
		newOpts := make([]manifest.Option, len(g.Options))
		for j := range g.Options {
			opt := g.Options[j]
			opt.Settings = pruneForPrompt(opt.Settings, preset)
			newOpts[j] = opt
		}
		g.Options = newOpts
		out = append(out, g)
	}
	return out
}

// mergeValues overlays value sets by layer (last wins), copying []string slices
// to avoid aliasing.
func mergeValues(layers ...settings.Values) settings.Values {
	out := make(settings.Values)
	for _, layer := range layers {
		for k, v := range layer {
			if list, ok := v.([]string); ok {
				cp := make([]string, len(list))
				copy(cp, list)
				out[k] = cp
				continue
			}
			out[k] = v
		}
	}
	return out
}
