package survey

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// FlowOptions controls [AskFlow] orchestration.
type FlowOptions struct {
	// Defaults — ask nothing; use defaults (+ preset).
	Defaults bool
	// Interactive — whether TTY is available. When false, asking is disabled:
	// unset groups use defaults, while an active string setting with empty default
	// and no preset returns [MissingRequiredError].
	Interactive bool
	// PresetSources labels preset-group origins (set|answer) for the summary.
	// Missing keys are treated as SourceSet.
	PresetSources map[string]Source
}

// MissingRequiredError — required string settings are unset in non-interactive
// mode (empty default, no preset).
type MissingRequiredError struct {
	// Groups — IDs of unset required groups (sorted).
	Groups []string
}

func (e *MissingRequiredError) Error() string {
	return "required string settings not set (set via --set): " + strings.Join(e.Groups, ", ")
}

// AskFlow orchestrates settings acquisition: applies preset (--set/--answers,
// highest priority), skips asking with opts.Defaults, validates required strings
// in non-interactive mode, or runs the interactive loop "ask → resolve → report/
// summary → confirm", repeating after rejection or resolver error. User abort
// ([huh.ErrUserAborted]) is propagated without creating anything.
func AskFlow(
	tpl *manifest.Template,
	preset settings.Values,
	opts FlowOptions,
	p Prompter,
	out io.Writer,
	pal ui.Palette,
) (settings.Resolved, error) {
	if preset == nil {
		preset = settings.Values{}
	}
	defaults := settings.DefaultValues(tpl)

	if opts.Defaults {
		return settings.Resolve(tpl, preset)
	}

	if !opts.Interactive {
		if missing := requiredMissing(tpl, defaults, preset); len(missing) > 0 {
			return settings.Resolved{}, &MissingRequiredError{Groups: missing}
		}
		return settings.Resolve(tpl, preset)
	}

	pruned := pruneForPrompt(tpl.Settings, preset)
	current := mergeValues(defaults, preset)
	for {
		asked, err := p.Ask(pruned, current)
		if err != nil {
			return settings.Resolved{}, err
		}
		// preset (--set/--answers) outranks input: overlay it last. Normally there
		// are no overlaps (preset groups are removed from prompts); this protects
		// the invariant "preset > prompt".
		explicit := mergeValues(asked, preset)

		resolved, rerr := settings.Resolve(tpl, explicit)
		if rerr != nil {
			fmt.Fprintln(out, pal.Error("Settings inconsistent: "+rerr.Error()))
			fmt.Fprintln(out, pal.Muted("Try again."))
			current = mergeValues(defaults, asked, preset)
			continue
		}

		printReport(out, pal, resolved.Report)
		summary := buildSummary(tpl, resolved, preset, asked, opts.PresetSources, pal)
		fmt.Fprintln(out, summary)

		ok, cerr := p.Confirm(summary)
		if cerr != nil {
			return settings.Resolved{}, cerr
		}
		if ok {
			return resolved, nil
		}
		current = mergeValues(defaults, asked, preset)
	}
}

// requiredMissing returns IDs of active string groups with empty values (empty
// default by convention) that are absent from preset.
func requiredMissing(tpl *manifest.Template, defaults, preset settings.Values) []string {
	cur := mergeValues(defaults, preset)
	valueOf := func(id string) any { return cur[id] }

	var missing []string
	walkActive(tpl.Settings, valueOf, func(g *manifest.SettingGroup) {
		if g.Type != manifest.TypeString {
			return
		}
		if _, set := preset[g.Group]; set {
			return
		}
		if s, _ := cur[g.Group].(string); s == "" {
			missing = append(missing, g.Group)
		}
	})
	sort.Strings(missing)
	return missing
}

// printReport prints resolver output: implied values and warnings.
func printReport(out io.Writer, pal ui.Palette, rep settings.Report) {
	if len(rep.Implied) > 0 {
		fmt.Fprintln(out, pal.Warn("Automatically enabled (required by selected options):"))
		for _, im := range rep.Implied {
			fmt.Fprintf(out, "  %s=%s (required by %s)\n", im.Group, im.Value, im.RequiredBy)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(out, pal.Muted("warning: "+w))
	}
}

// buildSummary builds a group/value/source table for active groups. Source priority
// is implied > prompt > preset (set/answer) > default. Implied values are marked implied.
func buildSummary(
	tpl *manifest.Template,
	resolved settings.Resolved,
	preset, asked settings.Values,
	presetSrc map[string]Source,
	pal ui.Palette,
) string {
	impliedBy := make(map[string]bool, len(resolved.Report.Implied))
	for _, im := range resolved.Report.Implied {
		impliedBy[im.Group] = true
	}

	tbl := ui.NewTable("Setting", "Value", "Source")
	valueOf := func(id string) any { return resolved.Values[id] }
	walkActive(tpl.Settings, valueOf, func(g *manifest.SettingGroup) {
		id := g.Group
		src := sourceOf(id, impliedBy, asked, preset, presetSrc)
		tbl.AddRow(id, formatValue(resolved.Values[id]), colorSource(pal, src))
	})

	return pal.Header("Settings summary:") + "\n" + tbl.RenderStyled(pal)
}

// sourceOf determines a group's source by priority.
func sourceOf(id string, impliedBy map[string]bool, asked, preset settings.Values, presetSrc map[string]Source) Source {
	switch {
	case impliedBy[id]:
		return SourceImplied
	case has(asked, id):
		return SourcePrompt
	case has(preset, id):
		if s, ok := presetSrc[id]; ok {
			return s
		}
		return SourceSet
	default:
		return SourceDefault
	}
}

// colorSource colors the source label (implied warning, default muted) for summaries.
func colorSource(pal ui.Palette, src Source) string {
	switch src {
	case SourceImplied:
		return pal.Warn(string(src))
	case SourceDefault:
		return pal.Muted(string(src))
	case SourceSet, SourceAnswer, SourcePrompt:
		return string(src)
	default:
		return string(src)
	}
}

// has reports whether a key is set in the values.
func has(v settings.Values, id string) bool {
	_, ok := v[id]
	return ok
}

// formatValue formats a group value for the summary.
func formatValue(v any) string {
	switch x := v.(type) {
	case []string:
		return strings.Join(x, ",")
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}
