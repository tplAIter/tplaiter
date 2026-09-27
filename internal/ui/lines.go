package ui

// SuccessLine формирует строку "✓ msg" — иконка в цвете успеха, текст как
// есть. Используется для итоговых однострочных сообщений (в отличие от
// [Palette.Success], который просто раскрашивает весь переданный текст).
func SuccessLine(pal Palette, msg string) string { return StatusIcon(pal, StatusOK) + " " + msg }

// WarnLine формирует строку "! msg" — иконка предупреждения.
func WarnLine(pal Palette, msg string) string { return StatusIcon(pal, StatusWarn) + " " + msg }

// ErrorLine формирует строку "✗ msg" — иконка ошибки. Используется, в
// частности, для префикса "error:" в main.go (см. [ErrorPrefix]).
func ErrorLine(pal Palette, msg string) string { return StatusIcon(pal, StatusFail) + " " + msg }

// InfoLine формирует приглушённую информационную строку "ℹ msg".
func InfoLine(pal Palette, msg string) string { return pal.Muted("ℹ") + " " + msg }

// ErrorPrefix раскрашивает префикс "error:" палитрой ошибки — отдельно от
// [ErrorLine], потому что main.go печатает префикс и текст ошибки как два
// разных Fprintln-аргумента (см. main.go), а не собирает одну строку.
func ErrorPrefix(pal Palette) string { return pal.Error("error:") }
