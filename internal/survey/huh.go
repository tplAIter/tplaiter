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

// HuhPrompter — боевая реализация [Prompter] поверх charmbracelet/huh. Zero-value
// пригоден к использованию: ввод/вывод по умолчанию — os.Stdin/os.Stdout, тема —
// стандартная тема huh.
type HuhPrompter struct {
	// In, Out — необязательные потоки формы (по умолчанию os.Stdin/os.Stdout).
	In  io.Reader
	Out io.Writer
	// Theme — необязательная тема huh (по умолчанию huh.ThemeCharm).
	Theme *huh.Theme
}

// binding хранит связанное с полем формы значение группы и указатель, который
// huh мутирует по ходу ввода. Для select/string/int используется s (int —
// строкой с int-валидацией), для multiselect — list, для toggle — b.
type binding struct {
	g    *manifest.SettingGroup
	s    string
	list []string
	b    bool
}

// value возвращает текущее значение биндинга в каноническом типе группы.
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

// newBinding создаёт биндинг группы, засеянный текущим значением cur (из
// дефолтов/preset/прошлой итерации опроса).
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

// field строит поле формы huh для группы, привязывая его к биндингу. Ошибка
// возвращается только при некомпилируемом pattern (валидатор манифеста обязан
// это отсекать раньше, но защищаемся).
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
				return nil, fmt.Errorf("группа %q: неверный pattern %q: %w", bd.g.Group, bd.g.Pattern, err)
			}
			in = in.Validate(v)
		}
		return in, nil
	default:
		return nil, fmt.Errorf("группа %q: неизвестный тип %q", bd.g.Group, bd.g.Type)
	}
}

// buildForm строит форму huh по дереву групп: одна huh-группа на настройку,
// вложенные скрыты через WithHideFunc до выбора активирующей опции предка.
// Возвращает форму и карту биндингов по id группы.
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

// ancestorsActive сообщает, что вся цепочка активирующих опций выбрана (значит
// вложенная группа должна быть видимой).
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

// Ask строит и запускает форму по активным группам, затем собирает значения
// только фактически активных групп (скрытые вложенные не попадают в результат —
// их разрешит [settings.Resolve] по выбору родителя).
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
		return nil, err // включая huh.ErrUserAborted
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

// Confirm показывает сводку и запрашивает согласие через huh.Confirm.
func (p HuhPrompter) Confirm(summary string) (bool, error) {
	var ok bool
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title("Применить эти настройки?").
			Description(summary).
			Affirmative("Да").
			Negative("Изменить").
			Value(&ok),
	))
	p.configure(form)
	if err := form.Run(); err != nil {
		return false, err
	}
	return ok, nil
}

// configure применяет необязательные потоки и тему к форме.
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

// selectableOptions разбивает опции группы на выбираемые (для huh) и planned
// (в подсказку). Для multiselect отмечает предвыбранные из preselected.
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

// fieldDescription собирает подсказку поля: описание группы плюс строку о
// planned-опциях (huh не умеет disabled-опции — честно перечисляем их отдельно).
func fieldDescription(g *manifest.SettingGroup, planned []string) string {
	d := g.Description
	if len(planned) > 0 {
		hint := "(planned — недоступно): " + strings.Join(planned, ", ")
		if d != "" {
			d += "\n" + hint
		} else {
			d = hint
		}
	}
	return d
}

// intValidator проверяет, что ввод — целое число.
func intValidator(s string) error {
	if _, err := strconv.Atoi(s); err != nil {
		return fmt.Errorf("значение %q не является целым числом", s)
	}
	return nil
}

// patternValidator компилирует pattern один раз и возвращает валидатор ввода.
func patternValidator(pattern string) (func(string) error, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return func(s string) error {
		if !re.MatchString(s) {
			return fmt.Errorf("значение не соответствует шаблону %s", pattern)
		}
		return nil
	}, nil
}

// groupTitle возвращает заголовок группы (title или id как запасной вариант).
func groupTitle(g *manifest.SettingGroup) string {
	if g.Title != "" {
		return g.Title
	}
	return g.Group
}

// optionTitle возвращает заголовок опции (title или id как запасной вариант).
func optionTitle(o *manifest.Option) string {
	if o.Title != "" {
		return o.Title
	}
	return o.ID
}
