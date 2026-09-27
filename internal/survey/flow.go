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

// FlowOptions управляет оркестрацией опроса [AskFlow].
type FlowOptions struct {
	// Defaults — не спрашивать ничего, взять дефолты (+ preset).
	Defaults bool
	// Interactive — доступен ли TTY. При false опрос запрещён: незаданные группы
	// берут дефолт, а активная строковая настройка с пустым дефолтом без preset —
	// ошибка [MissingRequiredError].
	Interactive bool
	// PresetSources размечает происхождение preset-групп (set|answer) для сводки.
	// Отсутствующие ключи считаются SourceSet.
	PresetSources map[string]Source
}

// MissingRequiredError — в неинтерактивном режиме не заданы обязательные
// строковые настройки (пустой дефолт, нет preset).
type MissingRequiredError struct {
	// Groups — id незаданных обязательных групп (отсортированы).
	Groups []string
}

func (e *MissingRequiredError) Error() string {
	return "не заданы обязательные строковые настройки (задайте через --set): " + strings.Join(e.Groups, ", ")
}

// AskFlow оркестрирует получение настроек: применяет preset
// (--set/--answers, приоритетнее всего), при opts.Defaults пропускает опрос,
// в неинтерактивном режиме проверяет обязательные строки, иначе ведёт
// интерактивный цикл «опрос → резолв → доклад/сводка → подтверждение» с
// переопросом при отказе или ошибке резолвера. Прерывание опросника
// ([huh.ErrUserAborted]) пробрасывается наружу без создания чего-либо.
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
		// preset (--set/--answers) приоритетнее ввода: кладём его последним слоем.
		// В норме пересечений нет (preset-группы вырезаны из опроса), слой —
		// защита инварианта «preset > prompt».
		explicit := mergeValues(asked, preset)

		resolved, rerr := settings.Resolve(tpl, explicit)
		if rerr != nil {
			fmt.Fprintln(out, pal.Error("Настройки не согласованы: "+rerr.Error()))
			fmt.Fprintln(out, pal.Muted("Повторите ввод."))
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

// requiredMissing возвращает id активных строковых групп с пустым значением
// (= пустой дефолт по договорённости ), не заданных в preset.
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

// printReport печатает доклад резолвера: довключённые значения и предупреждения.
func printReport(out io.Writer, pal ui.Palette, rep settings.Report) {
	if len(rep.Implied) > 0 {
		fmt.Fprintln(out, pal.Warn("Довключено автоматически (требуется выбранными опциями):"))
		for _, im := range rep.Implied {
			fmt.Fprintf(out, "  %s=%s (требует %s)\n", im.Group, im.Value, im.RequiredBy)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(out, pal.Muted("предупреждение: "+w))
	}
}

// buildSummary строит таблицу «группа/значение/источник» по активным группам
//. Источник определяется по приоритету implied > prompt > preset
// (set/answer) > default. Довключённые значения помечаются источником implied.
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

	tbl := ui.NewTable("Настройка", "Значение", "Источник")
	valueOf := func(id string) any { return resolved.Values[id] }
	walkActive(tpl.Settings, valueOf, func(g *manifest.SettingGroup) {
		id := g.Group
		src := sourceOf(id, impliedBy, asked, preset, presetSrc)
		tbl.AddRow(id, formatValue(resolved.Values[id]), colorSource(pal, src))
	})

	return pal.Header("Сводка настроек:") + "\n" + tbl.RenderStyled(pal)
}

// sourceOf определяет источник значения группы по приоритету.
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

// colorSource раскрашивает метку источника (implied — предупреждающим, default —
// приглушённым) для сводки.
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

// has сообщает, задан ли ключ в наборе значений.
func has(v settings.Values, id string) bool {
	_, ok := v[id]
	return ok
}

// formatValue форматирует значение группы для сводки.
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
