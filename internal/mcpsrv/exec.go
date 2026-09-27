package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Таймауты per-tool. Генерация проекта и обновление 3-way существенно дольше
// прочих команд (checkout, рендер, hooks) — им даётся расширенный лимит.
const (
	defaultTimeout = 120 * time.Second
	longTimeout    = 300 * time.Second
)

// runCLI исполняет подкоманду tplater в отдельном процессе (subprocess-паттерн
// goca): тот же бинарник (s.exe), аргументы отдельными элементами argv (без
// shell-интерполяции), рабочий каталог cwd, окружение — унаследованное
// (TPLAITER_HOME и прочее прокидывается автоматически, т.к. Env не задаётся).
// stdin НЕ подключается — интерактив исключён на уровне транспорта. Таймаут
// применяется через контекст: по истечении процесс убивается.
func (s *Server) runCLI(ctx context.Context, cwd string, argv []string, timeout time.Duration) (execx.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return s.runner.Run(ctx, s.exe, argv, execx.Options{Dir: cwd})
}

// toolResult транслирует результат подпроцесса в результат MCP-tool'а. Провал
// (ненулевой код возврата ИЛИ сбой запуска) даёт isError с полным stdout+stderr
// — агент должен видеть всю диагностику. Успех отдаёт stdout как текст (stderr
// добавляется отдельной секцией, если непуст: команды tplater пишут в stderr
// предупреждения, не только ошибки).
func toolResult(res execx.Result, runErr error) *mcp.CallToolResult {
	if failed(res, runErr) {
		return mcp.NewToolResultError(formatFailure(res, runErr))
	}

	out := res.Stdout
	if strings.TrimSpace(res.Stderr) != "" {
		out += "\n[stderr]\n" + res.Stderr
	}
	if strings.TrimSpace(out) == "" {
		out = "(команда завершилась успешно, вывод пуст)"
	}
	return mcp.NewToolResultText(out)
}

// failed определяет провал вызова: ненулевой код возврата подпроцесса ИЛИ
// ошибка запуска (бинарник не найден и т.п. — execx возвращает её без обёртки
// ExitError, с ExitCode -1).
func failed(res execx.Result, runErr error) bool {
	if res.ExitCode != 0 {
		return true
	}
	var exitErr *execx.ExitError
	// runErr != nil при ExitCode==0 маловероятно, но перестрахуемся: любую
	// ненулевую ошибку, кроме «чистого» ExitError с кодом 0, считаем провалом.
	return runErr != nil && !errors.As(runErr, &exitErr)
}

// formatFailure собирает диагностику провала: код возврата, stdout, stderr и
// (для сбоя запуска) текст самой ошибки.
func formatFailure(res execx.Result, runErr error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "команда завершилась с ошибкой (код возврата %d)\n", res.ExitCode)

	var exitErr *execx.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		fmt.Fprintf(&b, "ошибка запуска: %v\n", runErr)
	}
	if strings.TrimSpace(res.Stdout) != "" {
		b.WriteString("\n[stdout]\n")
		b.WriteString(res.Stdout)
	}
	if strings.TrimSpace(res.Stderr) != "" {
		b.WriteString("\n[stderr]\n")
		b.WriteString(res.Stderr)
	}
	return b.String()
}

// resolveWorkDir абсолютизирует и валидирует рабочий каталог tool'а: путь
// должен существовать и быть каталогом. Пустой dir → пустая строка (подпроцесс
// унаследует cwd сервера). Абсолютизация защищает от неоднозначности
// относительных путей относительно cwd сервера.
func resolveWorkDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("некорректный путь %q: %w", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("каталог %q недоступен: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q не является каталогом", abs)
	}
	return abs, nil
}

// resolveTargetDir абсолютизирует целевой каталог команды-создателя
// (init-template): сам каталог создаётся командой и существовать не обязан, но
// его родитель должен существовать, иначе писать некуда. Пустой dir → пустая
// строка (команда возьмёт дефолт ./<name>).
func resolveTargetDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("некорректный путь %q: %w", dir, err)
	}
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("родительский каталог %q недоступен: %w", parent, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q не является каталогом", parent)
	}
	return abs, nil
}
