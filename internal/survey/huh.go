package survey

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// HuhPrompter — production [Prompter] implementation over charmbracelet/huh.
// The zero value is usable: input/output default to os.Stdin/os.Stdout and the
// theme to huh's standard theme.
type HuhPrompter struct {
	// In, Out — optional form streams (default os.Stdin/os.Stdout).
	In  io.Reader
	Out io.Writer
	// Theme — optional huh theme (default huh.ThemeCharm).
	Theme *huh.Theme
}

// binding stores a group's form-field value and the pointer huh mutates during
// input. select/string/int use s (int as a string with integer validation),
// multiselect uses list, and toggle uses b.
type binding struct {
	g    *manifest.SettingGroup
	s    string
	list []string
	b    bool
}

// value returns the binding's current value in the group's canonical type.
func (bd *binding) value() any {
	switch bd.g.Type {
	case manifest.TypeMultiselect:
		cp := make([]string, len(bd.list))
		copy(cp, bd.list)
		return cp
	case manifest.TypeToggle:
		return bd.b
	case manifest.TypeInt:
		n, _ := strconv.Atoi(bd.s)
		return n
	case manifest.TypeSelect, manifest.TypeString:
		return bd.s
	default:
		return bd.s
	}
}

// newBinding creates a group binding seeded with cur (from defaults/preset/the
// previous questionnaire iteration).
func newBinding(g *manifest.SettingGroup, cur any) *binding {
	bd := &binding{g: g}
	switch g.Type {
	case manifest.TypeMultiselect:
		if list, ok := cur.([]string); ok {
			bd.list = make([]string, len(list))
			copy(bd.list, list)
		}
	case manifest.TypeToggle:
		if b, ok := cur.(bool); ok {
			bd.b = b
		}
	case manifest.TypeInt:
		switch n := cur.(type) {
		case int:
			bd.s = strconv.Itoa(n)
		case string:
			bd.s = n
		}
	case manifest.TypeSelect, manifest.TypeString:
		if s, ok := cur.(string); ok {
			bd.s = s
		}
	default:
		if s, ok := cur.(string); ok {
			bd.s = s
		}
	}
	return bd
}

// field builds a huh form field for a group and binds it. Errors occur only for
// an uncompilable pattern (the manifest validator should reject it earlier).
func (bd *binding) field() (huh.Field, error) {
	title := groupTitle(bd.g)
	switch bd.g.Type {
	case manifest.TypeSelect:
		opts, planned := selectableOptions(bd.g, nil)
		return huh.NewSelect[string]().
			Key(bd.g.Group).
			Title(title).
			Description(fieldDescription(bd.g, planned)).
			Options(opts...).
			Value(&bd.s), nil
	case manifest.TypeMultiselect:
		opts, planned := selectableOptions(bd.g, bd.list)
		return huh.NewMultiSelect[string]().
			Key(bd.g.Group).
			Title(title).
			Description(fieldDescription(bd.g, planned)).
			Options(opts...).
			Value(&bd.list), nil
	case manifest.TypeToggle:
		return huh.NewConfirm().
			Key(bd.g.Group).
			Title(title).
			Description(fieldDescription(bd.g, nil)).
			Value(&bd.b), nil
	case manifest.TypeInt:
		return huh.NewInput().
			Key(bd.g.Group).
			Title(title).
			Description(fieldDescription(bd.g, nil)).
			Validate(intValidator).
			Value(&bd.s), nil
	case manifest.TypeString:
		in := huh.NewInput().
			Key(bd.g.Group).
			Title(title).
			Description(fieldDescription(bd.g, nil)).
			Value(&bd.s)
		if bd.g.Pattern != "" {
			v, err := patternValidator(bd.g.Pattern)
			if err != nil {
				return nil, fmt.Errorf("group %q: invalid pattern %q: %w", bd.g.Group, bd.g.Pattern, err)
			}
			in = in.Validate(v)
		}
		return in, nil
	default:
		return nil, fmt.Errorf("group %q: unknown type %q", bd.g.Group, bd.g.Type)
	}
}

// buildForm builds a huh form from the group tree: one huh group per setting;
// nested groups stay hidden through WithHideFunc until their ancestor option is selected.
// Returns the form and bindings by group ID.
func buildForm(groups []manifest.SettingGroup, current settings.Values) (*huh.Form, map[string]*binding, error) {
	binds := make(map[string]*binding)
	var hgroups []*huh.Group
	var buildErr error

	flattenTree(groups, nil, func(g *manifest.SettingGroup, anc []ancestor) {
		if buildErr != nil {
			return
		}
		bd := newBinding(g, current[g.Group])
		binds[g.Group] = bd
		f, err := bd.field()
		if err != nil {
			buildErr = err
			return
		}
		hg := huh.NewGroup(f)
		if len(anc) > 0 {
			captured := anc
			hg = hg.WithHideFunc(func() bool { return !ancestorsActive(captured, binds) })
		}
		hgroups = append(hgroups, hg)
	})
	if buildErr != nil {
		return nil, nil, buildErr
	}
	return huh.NewForm(hgroups...), binds, nil
}

// ancestorsActive reports whether every activating option in the chain is selected
// (so the nested group should be visible).
func ancestorsActive(anc []ancestor, binds map[string]*binding) bool {
	for _, a := range anc {
		bd, ok := binds[a.group]
		if !ok {
			return false
		}
		if !optionSelected(bd.g.Type, bd.value(), a.option) {
			return false
		}
	}
	return true
}

// Ask builds and runs the form for active groups, then collects values only for
// actually active groups (hidden nested groups are omitted; [settings.Resolve]
// resolves them from the parent choice).
func (p HuhPrompter) Ask(groups []manifest.SettingGroup, current settings.Values) (settings.Values, error) {
	if len(groups) == 0 {
		return settings.Values{}, nil
	}
	form, binds, err := buildForm(groups, current)
	if err != nil {
		return nil, err
	}
	p.configure(form)
	if err := form.Run(); err != nil {
		return nil, err // including huh.ErrUserAborted
	}

	out := make(settings.Values)
	valueOf := func(id string) any {
		if bd, ok := binds[id]; ok {
			return bd.value()
		}
		return current[id]
	}
	walkActive(groups, valueOf, func(g *manifest.SettingGroup) {
		if bd, ok := binds[g.Group]; ok {
			out[g.Group] = bd.value()
		}
	})
	return out, nil
}

// Confirm shows the summary and asks for approval through huh.Confirm.
func (p HuhPrompter) Confirm(summary string) (bool, error) {
	var ok bool
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title("Apply these settings?").
			Description(summary).
			Affirmative("Yes").
			Negative("Change").
			Value(&ok),
	))
	p.configure(form)
	if err := form.Run(); err != nil {
		return false, err
	}
	return ok, nil
}

// configure applies optional streams and theme to the form.
func (p HuhPrompter) configure(form *huh.Form) {
	if p.In != nil {
		form.WithInput(p.In)
	}
	if p.Out != nil {
		form.WithOutput(p.Out)
	}
	if p.Theme != nil {
		form.WithTheme(p.Theme)
	}
}

// selectableOptions splits group options into selectable (for huh) and planned
// (for the hint). For multiselect it marks preselected values.
func selectableOptions(g *manifest.SettingGroup, preselected []string) (opts []huh.Option[string], planned []string) {
	for i := range g.Options {
		o := &g.Options[i]
		if o.Status == manifest.StatusPlanned {
			planned = append(planned, optionTitle(o))
			continue
		}
		opt := huh.NewOption(optionTitle(o), o.ID)
		for _, sel := range preselected {
			if sel == o.ID {
				opt = opt.Selected(true)
				break
			}
		}
		opts = append(opts, opt)
	}
	return opts, planned
}

// fieldDescription builds a field hint: group description plus planned options
// (huh cannot disable options, so they are listed separately).
func fieldDescription(g *manifest.SettingGroup, planned []string) string {
	d := g.Description
	if len(planned) > 0 {
		hint := "(planned — unavailable): " + strings.Join(planned, ", ")
		if d != "" {
			d += "\n" + hint
		} else {
			d = hint
		}
	}
	return d
}

// intValidator checks that input is an integer.
func intValidator(s string) error {
	if _, err := strconv.Atoi(s); err != nil {
		return fmt.Errorf("value %q is not an integer", s)
	}
	return nil
}

// patternValidator compiles pattern once and returns an input validator.
func patternValidator(pattern string) (func(string) error, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return func(s string) error {
		if !re.MatchString(s) {
			return fmt.Errorf("value does not match pattern %s", pattern)
		}
		return nil
	}, nil
}

// groupTitle returns the group title (or ID as fallback).
func groupTitle(g *manifest.SettingGroup) string {
	if g.Title != "" {
		return g.Title
	}
	return g.Group
}

// optionTitle returns the option title (or ID as fallback).
func optionTitle(o *manifest.Option) string {
	if o.Title != "" {
		return o.Title
	}
	return o.ID
}
