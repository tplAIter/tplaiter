// Package settings реализует модель значений настроек шаблона и резолвер
// (.3): типизированные значения групп, вычисление мини-языка
// условий [manifest.Condition], разбор CLI-значений (--set/--answers),
// транзитивное разрешение requires с довключением и детектом конфликтов/циклов,
// проверку constraints и построение контекста рендера с хелперами Is/Has.
//
// Пакет надстраивается над [manifest]: структуры дерева групп и синтаксис
// условий берутся оттуда, а вся семантика вычисления живёт здесь. Пакет
// [manifest] не импортирует settings и не изменяется этой реализацией.
package settings

import (
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Values — набор значений настроек: id группы → значение согласно типу группы.
// Тип значения канонический: string для select/string, []string для
// multiselect, bool для toggle, int для int. Значения хранятся плоско по id
// группы (id глобально уникальны, включая вложенные — гарантирует валидатор
// манифеста).
type Values map[string]any

// Clone возвращает поверхностную копию значений с копированием []string-срезов,
// чтобы мутации производного набора не протекали в исходный.
func (v Values) Clone() Values {
	out := make(Values, len(v))
	for k, val := range v {
		if list, ok := val.([]string); ok {
			cp := make([]string, len(list))
			copy(cp, list)
			out[k] = cp
			continue
		}
		out[k] = val
	}
	return out
}

// groupMeta — сведения о группе и её активирующем родителе для обхода дерева.
// parentGroup == "" — корневая группа (активна всегда). Иначе группа активна,
// когда в parentGroup выбрана опция parentOption (и сам parentGroup активен).
type groupMeta struct {
	g           *manifest.SettingGroup
	parentGroup string
	parentOpt   string
}

// optionMeta — опция select/multiselect-группы с обратной ссылкой на группу.
type optionMeta struct {
	opt   *manifest.Option
	group string
}

// indexGroups строит плоскую карту id группы → метаданные (тип, дефолт,
// родитель) обходом всего дерева настроек, включая вложенные уточнения.
func indexGroups(tpl *manifest.Template) map[string]groupMeta {
	idx := make(map[string]groupMeta)
	var walk func(groups []manifest.SettingGroup, parentGroup, parentOpt string)
	walk = func(groups []manifest.SettingGroup, parentGroup, parentOpt string) {
		for i := range groups {
			g := &groups[i]
			if _, dup := idx[g.Group]; !dup {
				idx[g.Group] = groupMeta{g: g, parentGroup: parentGroup, parentOpt: parentOpt}
			}
			for j := range g.Options {
				opt := &g.Options[j]
				walk(opt.Settings, g.Group, opt.ID)
			}
		}
	}
	walk(tpl.Settings, "", "")
	return idx
}

// indexOptions строит карту "group=optionID" → опция для select/multiselect
// групп. Ключ совпадает с каноническим видом атома условия (§3.2), что
// позволяет напрямую связывать requires-атомы с опциями.
func indexOptions(tpl *manifest.Template) map[string]optionMeta {
	idx := make(map[string]optionMeta)
	var walk func(groups []manifest.SettingGroup)
	walk = func(groups []manifest.SettingGroup) {
		for i := range groups {
			g := &groups[i]
			for j := range g.Options {
				opt := &g.Options[j]
				if g.Type == manifest.TypeSelect || g.Type == manifest.TypeMultiselect {
					key := g.Group + manifest.OpEq + opt.ID
					if _, dup := idx[key]; !dup {
						idx[key] = optionMeta{opt: opt, group: g.Group}
					}
				}
				walk(opt.Settings)
			}
		}
	}
	walk(tpl.Settings)
	return idx
}

// DefaultValues возвращает значения по умолчанию ВСЕХ групп дерева, включая
// вложенные уточнения. Дефолты вложенных групп применяются всегда; «активность»
// (учёт выбора родителя) вычисляется отдельно в [Resolve] через ActiveValues.
func DefaultValues(tpl *manifest.Template) Values {
	v := make(Values)
	for id, m := range indexGroups(tpl) {
		v[id] = defaultFor(m.g)
	}
	return v
}

// defaultFor приводит manifest-дефолт группы к каноническому Go-типу. При
// отсутствии дефолта возвращает zero-значение типа.
func defaultFor(g *manifest.SettingGroup) any {
	if g.Default == nil {
		return zeroValue(g.Type)
	}
	switch g.Type {
	case manifest.TypeSelect:
		if s, ok := g.Default.(string); ok {
			return s
		}
	case manifest.TypeMultiselect:
		return toStringSlice(g.Default)
	case manifest.TypeToggle:
		if b, ok := g.Default.(bool); ok {
			return b
		}
	case manifest.TypeString:
		if s, ok := g.Default.(string); ok {
			return s
		}
	case manifest.TypeInt:
		if n, ok := toInt(g.Default); ok {
			return n
		}
	}
	return zeroValue(g.Type)
}

// zeroValue — пустое значение канонического типа группы: "" для select/string,
// пустой []string для multiselect, false для toggle, 0 для int.
func zeroValue(typ string) any {
	switch typ {
	case manifest.TypeMultiselect:
		return []string{}
	case manifest.TypeToggle:
		return false
	case manifest.TypeInt:
		return 0
	default: // select, string и неизвестные
		return ""
	}
}

// toStringSlice приводит yaml-значение (обычно []any) к []string.
func toStringSlice(v any) []string {
	switch list := v.(type) {
	case []string:
		out := make([]string, len(list))
		copy(out, list)
		return out
	case []any:
		out := make([]string, 0, len(list))
		for _, el := range list {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

// toInt приводит числовое yaml-значение к int (int, int64, float64 без
// дробной части).
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// contains сообщает, содержит ли срез значение.
func contains(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}
