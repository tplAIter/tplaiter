package selfupdate

import (
	"context"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// LatestTag возвращает старший тег вида v* (SemVer) удалённого репозитория
// repoURL через `git ls-remote --tags`. Пустая строка без ошибки означает
// «в репозитории нет ни одного v*-тега».
func LatestTag(ctx context.Context, runner execx.Runner, repoURL string) (string, error) {
	res, err := runner.Run(ctx, "git", []string{"ls-remote", "--tags", repoURL}, execx.Options{})
	if err != nil {
		return "", fmt.Errorf("selfupdate: git ls-remote --tags %s: %w", repoURL, err)
	}
	return parseLatestTag(res.Stdout), nil
}

// parseLatestTag разбирает вывод `git ls-remote --tags` (строки вида
// "<sha>\trefs/tags/<ref>") и возвращает старший корректный v*-SemVer тег.
// Невалидные (не начинающиеся с "v" или не парсящиеся как SemVer) строки и
// dereferenced-ссылки на annotated-теги ("^{}") игнорируются молча — это не
// ошибка формата, просто шум, обычный для ls-remote.
func parseLatestTag(output string) string {
	var (
		latest    *semver.Version
		latestRaw string
	)

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		ref := strings.TrimSuffix(strings.TrimPrefix(fields[1], "refs/tags/"), "^{}")
		if !strings.HasPrefix(ref, "v") {
			continue
		}
		v, err := semver.NewVersion(ref)
		if err != nil {
			continue
		}
		if latest == nil || v.GreaterThan(latest) {
			latest = v
			latestRaw = ref
		}
	}
	return latestRaw
}

// CompareResult — итог сравнения текущей версии CLI со старшим найденным
// тегом (см. [Compare]).
type CompareResult int

// Возможные результаты [Compare].
const (
	// CompareUnknown — сравнить невозможно: одна из версий (обычно текущая —
	// локальная "dev"-сборка) не является корректным SemVer.
	CompareUnknown CompareResult = iota
	// CompareUpToDate — текущая версия равна latest.
	CompareUpToDate
	// CompareOutdated — текущая версия старше latest, есть смысл обновиться.
	CompareOutdated
	// CompareAhead — текущая версия новее latest (локальная/pre-release
	// сборка опережает опубликованные теги) — обновление не требуется.
	CompareAhead
)

// Compare сравнивает current (обычно результат `tplater version`) с latest
// (результат [LatestTag]). Префикс "v" в обоих аргументах необязателен.
func Compare(current, latest string) CompareResult {
	cv, err := semver.NewVersion(strings.TrimPrefix(current, "v"))
	if err != nil {
		return CompareUnknown
	}
	lv, err := semver.NewVersion(strings.TrimPrefix(latest, "v"))
	if err != nil {
		return CompareUnknown
	}

	switch {
	case cv.LessThan(lv):
		return CompareOutdated
	case cv.GreaterThan(lv):
		return CompareAhead
	default:
		return CompareUpToDate
	}
}
