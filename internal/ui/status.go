package ui

// StatusKind — семантический статус одной позиции отчёта/строки таблицы:
// проверка окружения (doctor), доступность записи реестра (projects list),
// выполнимость when-условия (run/env/gen/ai list), объявленная-но-не-
// реализованная опция манифеста (template show, planned).
type StatusKind int

const (
	// StatusOK — проверка/позиция в порядке.
	StatusOK StatusKind = iota
	// StatusWarn — не критично, но требует внимания (необязательный
	// инструмент не найден, запись реестра под вопросом).
	StatusWarn
	// StatusFail — критично (обязательный инструмент не найден, ошибка).
	StatusFail
	// StatusPlanned — заявлено манифестом, но ещё не реализовано (
	// "честность каталога": planned-опции показываются, но приглушённо).
	StatusPlanned
)

// StatusIcon возвращает символ статуса, окрашенный палитрой pal: ✓ (OK),
// ! (Warn), ✗ (Fail), ○ (Planned, приглушённый). При pal.Enabled() == false
// возвращает символ без ANSI-раскраски (иконка остаётся — она несёт смысл
// сама по себе, в отличие от цвета).
func StatusIcon(pal Palette, kind StatusKind) string {
	switch kind {
	case StatusOK:
		return pal.Success("✓")
	case StatusWarn:
		return pal.Warn("!")
	case StatusFail:
		return pal.Error("✗")
	case StatusPlanned:
		return pal.Muted("○")
	default:
		return ""
	}
}
