package settings

import "github.com/tplAIter/tplaiter/internal/manifest"

// View — представление активных значений настроек для движка рендера.
// Как именованный тип map[string]any допускает доступ `.Settings.<group>` в
// шаблонах и одновременно несёт методы-хелперы Is/Has (§3.1). Движок (реализация )
// может дополнительно зарегистрировать их как функции FuncMap `is`/`has`.
type View map[string]any

// Is сообщает, равно ли значение группы заданному (select/string — равенство,
// toggle — сравнение с true/false, int — числовое). Для multiselect используйте
// [View.Has].
func (s View) Is(group, value string) bool {
	raw, ok := s[group]
	if !ok {
		return false
	}
	if _, isList := raw.([]string); isList {
		return false
	}
	return matchValue(raw, value)
}

// Has сообщает, содержит ли multiselect-группа заданное значение. Для
// не-multiselect всегда false.
func (s View) Has(group, value string) bool {
	list, ok := s[group].([]string)
	if !ok {
		return false
	}
	return contains(list, value)
}

// RenderContext строит контекст движка рендера из разрешённых настроек:
// `.Settings` — активные значения (View с хелперами Is/Has). реализация
// дополняет контекст проектными полями (Project/Name/…) и подключает Is/Has в
// FuncMap.
func RenderContext(_ *manifest.Template, resolved Resolved) map[string]any {
	return map[string]any{
		"Settings": View(resolved.ActiveValues),
	}
}
