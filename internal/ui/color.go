package ui

import (
	"os"

	"golang.org/x/term"
)

// ColorEnabled сообщает, разрешён ли цветной вывод для stdout текущего
// процесса. Правила (по приоритету):
//  1. NO_COLOR задан (любое значение, см. https://no-color.org/) -> false;
//  2. CLICOLOR_FORCE задан и не "0" -> true, даже если stdout не TTY;
//  3. иначе — true только если stdout — терминал.
func ColorEnabled() bool {
	return colorEnabled(os.Getenv("NO_COLOR"), os.Getenv("CLICOLOR_FORCE"), isTerminal(os.Stdout))
}

// colorEnabled — чистая функция без побочных эффектов, вынесена для юнит-тестов.
func colorEnabled(noColor, forceColor string, stdoutIsTTY bool) bool {
	if noColor != "" {
		return false
	}
	if forceColor != "" && forceColor != "0" {
		return true
	}
	return stdoutIsTTY
}

// isTerminal сообщает, подключён ли f к терминалу.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
