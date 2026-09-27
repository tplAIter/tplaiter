// Package survey реализует интерактивный опросник настроек шаблона:
// строит формы charmbracelet/huh по дереву групп [manifest.SettingGroup],
// оркестрирует опрос (AskFlow), а результат прогоняет через резолвер
// [settings.Resolve] с докладом довключений и сводкой источников значений.
//
// Пакет надстраивается над [settings] (модель значений и резолвер) и
// [manifest] (структура дерева групп) и не изменяет их. Точка тестируемости —
// интерфейс [Prompter]: боевая реализация [HuhPrompter] рисует TUI, тестовая
// [ScriptedPrompter] проигрывает заранее заданные ответы без TTY.
package survey

import (
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Prompter — абстракция ввода настроек, отделяющая оркестрацию опроса от
// конкретного UI. Ask опрашивает переданное (уже урезанное до незаданных)
// дерево групп, отталкиваясь от текущих значений current; Confirm показывает
// сводку и запрашивает подтверждение. Обе операции возвращают
// [huh.ErrUserAborted] при прерывании пользователем (Ctrl+C) — оркестратор
// пробрасывает её наружу.
type Prompter interface {
	// Ask опрашивает активные группы дерева groups, начиная со значений current,
	// и возвращает значения только фактически заданных (активных) групп.
	Ask(groups []manifest.SettingGroup, current settings.Values) (settings.Values, error)
	// Confirm показывает summary и возвращает согласие пользователя.
	Confirm(summary string) (bool, error)
}

// Проверки соответствия интерфейсу на этапе компиляции.
var (
	_ Prompter = HuhPrompter{}
	_ Prompter = (*ScriptedPrompter)(nil)
)

// Source — источник итогового значения группы для сводки.
type Source string

// Возможные источники значения настройки.
const (
	SourceSet     Source = "set"     // из --set
	SourceAnswer  Source = "answer"  // из --answers
	SourceDefault Source = "default" // дефолт манифеста
	SourcePrompt  Source = "prompt"  // введено в опросе
	SourceImplied Source = "implied" // довключено резолвером
)

// ancestor — активирующая пара (группа, опция) на пути к вложенной группе.
type ancestor struct {
	group  string
	option string
}

// optionSelected сообщает, выбрана ли опция optID в группе типа select/
// multiselect при значении val.
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

// selectedOptionIDs возвращает id выбранных опций группы при значении val
// (для select — не более одной, для multiselect — список). Для не-опционных
// типов — nil.
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

// walkActive обходит дерево групп в порядке объявления, вызывая fn для каждой
// АКТИВНОЙ группы: корневые активны всегда, вложенные — когда в родительской
// группе выбрана активирующая опция (значение берётся через valueOf).
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

// flattenTree обходит ВСЁ дерево (без учёта выбора — динамику берёт на себя
// huh через WithHideFunc), передавая fn каждую группу с её цепочкой
// активирующих предков.
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

// pruneForPrompt возвращает поддерево групп, которое нужно опросить
// интерактивно: группы, уже зафиксированные preset (--set/--answers), из
// вопросов исключаются, а всё ещё активные вложенные уточнения выбранной
// preset-опции поднимаются на текущий уровень (их родитель зафиксирован —
// значит они безусловно активны и не нуждаются в WithHideFunc). Группы, не
// заданные в preset, сохраняют вложенность (динамическое раскрытие остаётся за
// опросником).
func pruneForPrompt(groups []manifest.SettingGroup, preset settings.Values) []manifest.SettingGroup {
	out := make([]manifest.SettingGroup, 0, len(groups))
	for i := range groups {
		g := groups[i] // копия узла (Options переопределим ниже)
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

// mergeValues накладывает наборы значений в порядке слоёв (последний
// побеждает), копируя []string-срезы, чтобы исключить алиасинг.
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
