package contribute

import (
	"io"

	"github.com/charmbracelet/huh"
)

// FilePicker selects a subset of candidate files to contribute to the template.
// The production implementation is a huh multiselect ([HuhPicker]); tests use
// deterministic [ScriptedPicker]. survey.Prompter is unsuitable here: it asks
// about the manifest's settings-group tree rather than an arbitrary path list.
type FilePicker interface {
	// Pick shows a multiselect for candidates (all preselected) and returns the
	// selected paths. An empty candidates list returns empty without a dialog.
	Pick(candidates []string) ([]string, error)
}

// HuhPicker — multiselect over charmbracelet/huh (the same engine as
// survey.HuhPrompter). The zero value is usable: input/output default to
// os.Stdin/os.Stdout, and the theme defaults to huh's standard theme.
type HuhPicker struct {
	// In, Out — optional form streams (defaulting to os.Stdin/os.Stdout).
	In  io.Reader
	Out io.Writer
	// Theme — optional huh theme (defaulting to huh.ThemeCharm).
	Theme *huh.Theme
}

// Pick implements [FilePicker] through huh.MultiSelect with preselected options.
func (p HuhPicker) Pick(candidates []string) ([]string, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	selected := append([]string(nil), candidates...)

	opts := make([]huh.Option[string], 0, len(candidates))
	for _, c := range candidates {
		opts = append(opts, huh.NewOption(c, c).Selected(true))
	}

	form := huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title("Файлы для вклада в шаблон").
			Description("Отмеченные файлы будут де-параметризованы и предложены в MR").
			Options(opts...).
			Value(&selected),
	))
	if p.In != nil {
		form.WithInput(p.In)
	}
	if p.Out != nil {
		form.WithOutput(p.Out)
	}
	if p.Theme != nil {
		form.WithTheme(p.Theme)
	}
	if err := form.Run(); err != nil {
		return nil, err // including huh.ErrUserAborted
	}
	return selected, nil
}

// ScriptedPicker — deterministic [FilePicker] implementation for tests and
// non-interactive scenarios. Nil fields define the behavior: Choose=nil returns
// all candidates (the default selection); Choose!=nil returns exactly what the
// function returns.
type ScriptedPicker struct {
	// Choose, when set, fully determines the result for the candidate list.
	Choose func(candidates []string) []string
}

// Pick implements [FilePicker].
func (p ScriptedPicker) Pick(candidates []string) ([]string, error) {
	if p.Choose != nil {
		return p.Choose(candidates), nil
	}
	return append([]string(nil), candidates...), nil
}
