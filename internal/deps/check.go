// Package deps — детект и установка инструментов окружения, объявленных в
// requires.tools манифеста шаблона (SPEC-03 §4). Весь запуск внешних команд
// идёт через [execx.Runner] — пакет не трогает os/exec напрямую и полностью
// покрывается юнитами через execx.RecordingRunner.
package deps

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ErrExecutionUnavailable marks the deliberately closed generic dependency
// execution surface. Version probes are not an authority to start a process.
var ErrExecutionUnavailable = errors.New("deps: execution unavailable")

// ToolStatus — результат проверки одного инструмента из requires.tools.
type ToolStatus struct {
	// Tool — исходное требование манифеста, по которому построен статус.
	Tool manifest.Tool
	// Found сообщает, найден ли бинарник в PATH (см. [execx.Runner.LookPath]).
	Found bool
	// Path — путь к бинарнику, если Found.
	Path string
	// Version — нормализованная (major.minor.patch) версия инструмента, если
	// её удалось определить и распарсить. Пусто, если версия не нужна для
	// Tool.Version (constraint пуст) детект всё равно предпринимается —
	// поле полезно для отчёта doctor независимо от constraint.
	Version string
	// Satisfies — true, если Found и (Tool.Version пуст, либо Version
	// удовлетворяет constraint). false при любой проблеме — детали в Err.
	Satisfies bool
	// Err — причина, по которой Found/Satisfies не выставлены в true:
	// бинарник не найден, версию не удалось выполнить/распарсить, constraint
	// не разобран. nil, если всё хорошо.
	Err error
}

// Check проверяет каждый инструмент из tools: ищет бинарник в PATH через
// runner.LookPath, затем (если найден) определяет его версию и сверяет с
// Tool.Version. Порядок результата соответствует порядку tools.
func Check(ctx context.Context, runner execx.Runner, tools []manifest.Tool) []ToolStatus {
	statuses := make([]ToolStatus, 0, len(tools))
	for _, tool := range tools {
		statuses = append(statuses, ToolStatus{Tool: tool, Err: ErrExecutionUnavailable})
	}
	return statuses
}

func checkOne(ctx context.Context, runner execx.Runner, tool manifest.Tool) ToolStatus {
	st := ToolStatus{Tool: tool}

	path, err := runner.LookPath(tool.Name)
	if err != nil {
		st.Err = fmt.Errorf("deps: %s не найден в PATH: %w", tool.Name, err)
		return st
	}
	st.Found = true
	st.Path = path

	raw, err := detectVersion(ctx, runner, tool.Name)
	if err != nil {
		st.Err = fmt.Errorf("deps: определение версии %s: %w", tool.Name, err)
		return st
	}

	version, ok := normalizeVersion(raw)
	if !ok {
		st.Err = fmt.Errorf("deps: не удалось разобрать версию %s из %q", tool.Name, raw)
		return st
	}
	st.Version = version

	satisfies, err := satisfiesConstraint(version, tool.Version)
	if err != nil {
		st.Err = fmt.Errorf("deps: constraint %q инструмента %s: %w", tool.Version, tool.Name, err)
		return st
	}
	st.Satisfies = satisfies
	return st
}

// toolDetector описывает, как определить версию конкретного инструмента:
// упорядоченный список попыток команд (первая успешная используется) и
// функцию извлечения версии-подобного токена из её вывода.
type toolDetector struct {
	attempts [][]string
	extract  func(output string) (string, bool)
}

// detectors — таблица override для инструментов с нестандартным форматом
// вывода версии (SPEC-03 §4).
var detectors = map[string]toolDetector{
	// `go version` -> "go version go1.26.4 darwin/arm64".
	"go": {
		attempts: [][]string{{"version"}},
		extract:  extractGoVersion,
	},
	// Docker Desktop/CLI не всегда поднят демон — сначала пробуем
	// клиентскую версию через --format (не требует живого демона), при
	// ошибке (старые версии docker без --format) — обычный --version.
	"docker": {
		attempts: [][]string{
			{"version", "--format", "{{.Client.Version}}"},
			{"--version"},
		},
		extract: extractGenericVersion,
	},
	// `ansible --version` -> первая строка "ansible [core 2.16.3]" (2.10+)
	// либо "ansible 2.9.27" (устаревшие).
	"ansible": {
		attempts: [][]string{{"--version"}},
		extract:  extractAnsibleVersion,
	},
}

// defaultDetector — generic-детектор для инструментов без записи в
// [detectors]: `<name> --version`, первый semver-подобный токен из вывода.
var defaultDetector = toolDetector{
	attempts: [][]string{{"--version"}},
	extract:  extractGenericVersion,
}

func detectorFor(name string) toolDetector {
	if d, ok := detectors[name]; ok {
		return d
	}
	return defaultDetector
}

// detectVersion выполняет команды детектора name по очереди, пока одна не
// вернёт вывод, из которого extract смог достать версию-подобный токен.
func detectVersion(ctx context.Context, runner execx.Runner, name string) (string, error) {
	d := detectorFor(name)

	var lastErr error
	for _, args := range d.attempts {
		res, err := runner.Run(ctx, name, args, execx.Options{})
		if err != nil {
			lastErr = err
			continue
		}
		output := res.Stdout
		if strings.TrimSpace(output) == "" {
			output = res.Stderr
		}
		token, ok := d.extract(output)
		if ok {
			return token, nil
		}
		lastErr = fmt.Errorf("не удалось найти версию в выводе %q", firstLine(output))
	}
	if lastErr == nil {
		lastErr = errors.New("нет ни одной попытки определения версии")
	}
	return "", lastErr
}

// genericVersionRe ищет первый semver-подобный токен ("1", "1.26",
// "1.26.4", с опциональным "v"-префиксом) в произвольном выводе.
var genericVersionRe = regexp.MustCompile(`v?(\d+(?:\.\d+){0,2})`)

func extractGenericVersion(output string) (string, bool) {
	m := genericVersionRe.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// goVersionRe выделяет версию из `go version` ("go1.26.4" -> "1.26.4").
var goVersionRe = regexp.MustCompile(`go(\d+(?:\.\d+){0,2})`)

func extractGoVersion(output string) (string, bool) {
	m := goVersionRe.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// extractAnsibleVersion берёт только первую строку вывода (остальные строки
// — версии python/jinja2/зависимостей, которые не должны перебивать основную
// версию ansible) и ищет в ней generic-токен.
func extractAnsibleVersion(output string) (string, bool) {
	return extractGenericVersion(firstLine(output))
}

// normalizeVersion приводит «грязную» версию к каноничному major.minor.patch
// (Masterminds/semver сам достраивает недостающие minor/patch нулями, но
// String() возвращает уже полную тройку — например, "1.26" -> "1.26.0").
func normalizeVersion(raw string) (string, bool) {
	v, err := semver.NewVersion(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	return v.String(), true
}

// satisfiesConstraint сообщает, удовлетворяет ли version ограничению
// constraint. Пустой constraint удовлетворяется любой версией (манифест не
// требует конкретной версии — важно только присутствие инструмента).
func satisfiesConstraint(version, constraint string) (bool, error) {
	if strings.TrimSpace(constraint) == "" {
		return true, nil
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("разбор версии %q: %w", version, err)
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("разбор constraint %q: %w", constraint, err)
	}
	return c.Check(v), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
