package contribute

import (
	"io"

	"github.com/charmbracelet/huh"
)

// FilePicker выбирает подмножество файлов-кандидатов для вклада в шаблон
//. Боевая реализация — huh-мультиселект ([HuhPicker]); тесты
// подставляют детерминированный [ScriptedPicker]. survey.Prompter здесь не
// подходит: он опрашивает дерево групп настроек манифеста, а не произвольный
// список путей.
type FilePicker interface {
	// Pick показывает мультиселект по candidates (все предвыбраны) и возвращает
	// отмеченные пути. Пустой список candidates → пустой результат без диалога.
	Pick(candidates []string) ([]string, error)
}

// HuhPicker — мультиселект поверх charmbracelet/huh (тот же движок, что у
// survey.HuhPrompter). Zero-value пригоден: ввод/вывод по умолчанию — os.Stdin/
// os.Stdout, тема — стандартная тема huh.
type HuhPicker struct {
	// In, Out — необязательные потоки формы (по умолчанию os.Stdin/os.Stdout).
	In  io.Reader
	Out io.Writer
	// Theme — необязательная тема huh (по умолчанию huh.ThemeCharm).
	Theme *huh.Theme
}

// Pick реализует [FilePicker] через huh.MultiSelect с предвыбранными опциями.
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
		return nil, err // включая huh.ErrUserAborted
	}
	return selected, nil
}

// ScriptedPicker — детерминированная реализация [FilePicker] для тестов и
// неинтерактивных сценариев. Nil-значение полей задаёт поведение: Choose=nil →
// вернуть все кандидаты (предвыбор по умолчанию); Choose!=nil → вернуть ровно
// то, что вернёт функция.
type ScriptedPicker struct {
	// Choose, если задана, полностью определяет результат по списку кандидатов.
	Choose func(candidates []string) []string
}

// Pick реализует [FilePicker].
func (p ScriptedPicker) Pick(candidates []string) ([]string, error) {
	if p.Choose != nil {
		return p.Choose(candidates), nil
	}
	return append([]string(nil), candidates...), nil
}
