package update

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/tplAIter/tplaiter/internal/ui"
)

// FileDelta — файл с числом добавленных/удалённых строк относительно эталона.
type FileDelta struct {
	Path    string
	Added   int
	Removed int
}

// Report — структурированный отчёт update по 5 категориям,
// построенный из плана ДО его применения (чтобы читать текущее рабочее дерево).
type Report struct {
	// Updated — файлы, перезаписанные target-версией (hash==baseline, правил
	// только шаблон): «обновлено».
	Updated []string
	// KeptYours — файлы, которые шаблон не менял, а пользователь правил:
	// «сохранено ваше».
	KeptYours []string
	// Merged — файлы, слитые 3-way без конфликта, с числом ±строк.
	Merged []FileDelta
	// Conflicts — файлы с маркерами конфликта: «КОНФЛИКТ».
	Conflicts []string
	// LocalDeviations — «локальные отклонения»: файлы, где рабочее дерево
	// отличается от эталонного base-рендера И шаблон их тоже менял (категории c
	// merge+conflict). Для них показывается унифицированный diff work↔baseline.
	LocalDeviations []FileDelta
	// Deleted — файлы, удалённые вслед за шаблоном.
	Deleted []string
	// Created — новые файлы target-версии.
	Created []string
	// Warnings — предупреждения плана (напр. удалён вверху, изменён локально).
	Warnings []string
	// diffs — унифицированные diff work↔baseline для LocalDeviations (для --verbose).
	diffs map[string]string
}

// buildReport классифицирует действия плана по категориям отчёта. baseFiles —
// чистый рендер старой версии (эталон для diff «сделано не по шаблону»); workDir
// — корень проекта (рабочее дерево ещё не изменено планом).
func buildReport(plan *Plan, baseFiles map[string][]byte, workDir string) *Report {
	r := &Report{diffs: map[string]string{}}
	r.Warnings = append(r.Warnings, plan.Warnings...)

	for _, a := range plan.Actions {
		switch {
		case a.Conflict:
			r.Conflicts = append(r.Conflicts, a.Path)
			r.addDeviation(a.Path, baseFiles, workDir)
		case a.Op == OpDelete:
			r.Deleted = append(r.Deleted, a.Path)
		case a.Op == OpWrite && a.Reason == "merge":
			work, _, _ := readWork(workDir, a.Path)
			add, rm := lineDelta(work, a.Content)
			r.Merged = append(r.Merged, FileDelta{Path: a.Path, Added: add, Removed: rm})
			r.addDeviation(a.Path, baseFiles, workDir)
		case a.Op == OpWrite && a.Reason == "create":
			r.Created = append(r.Created, a.Path)
		case a.Op == OpWrite: // update / recreate
			r.Updated = append(r.Updated, a.Path)
		case a.Op == OpKeep && a.Reason == "unchanged":
			// keep без пользовательской правки — не шумим (файл идентичен эталону).
			work, _, _ := readWork(workDir, a.Path)
			if base, ok := baseFiles[a.Path]; ok && !bytes.Equal(work, base) {
				r.KeptYours = append(r.KeptYours, a.Path)
			}
		case a.Op == OpKeep && a.Reason == "kept (modified locally, removed upstream)":
			r.KeptYours = append(r.KeptYours, a.Path)
		}
	}

	sort.Strings(r.Updated)
	sort.Strings(r.KeptYours)
	sort.Strings(r.Conflicts)
	sort.Strings(r.Deleted)
	sort.Strings(r.Created)
	sort.Slice(r.Merged, func(i, j int) bool { return r.Merged[i].Path < r.Merged[j].Path })
	sort.Slice(r.LocalDeviations, func(i, j int) bool { return r.LocalDeviations[i].Path < r.LocalDeviations[j].Path })
	return r
}

// addDeviation регистрирует файл как локальное отклонение (work != base-рендер),
// сохраняя unified diff work↔baseline для --verbose.
func (r *Report) addDeviation(path string, baseFiles map[string][]byte, workDir string) {
	base, ok := baseFiles[path]
	if !ok {
		return
	}
	work, _, _ := readWork(workDir, path)
	if bytes.Equal(work, base) {
		return
	}
	add, rm := lineDelta(base, work)
	r.LocalDeviations = append(r.LocalDeviations, FileDelta{Path: path, Added: add, Removed: rm})
	r.diffs[path] = unifiedDiff(base, work)
}

// HasConflicts сообщает, есть ли файлы с конфликт-маркерами.
func (r *Report) HasConflicts() bool { return len(r.Conflicts) > 0 }

// Render печатает отчёт в out палитрой pal. verbose добавляет унифицированный
// diff для каждого файла из «локальных отклонений».
func (r *Report) Render(out io.Writer, pal ui.Palette, verbose bool) {
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintln(out, title)
		for _, it := range items {
			fmt.Fprintf(out, "  %s\n", it)
		}
	}

	// Категории с явной семантикой окрашены соответствующим цветом палитры
	// (обновлено=success, конфликт=error, отклонения=warn — реализация реализацию);
	// нейтральные категории — просто жирным заголовком ([ui.Palette.Header]).
	section(pal.Success("обновлено:"), r.Updated)
	section(pal.Header("создано:"), r.Created)
	section(pal.Header("удалено:"), r.Deleted)
	section(pal.Header("сохранено ваше:"), r.KeptYours)

	if len(r.Merged) > 0 {
		fmt.Fprintln(out, pal.Header("смержено:"))
		for _, d := range r.Merged {
			fmt.Fprintf(out, "  %s (%s)\n", d.Path, deltaStr(pal, d))
		}
	}
	if len(r.Conflicts) > 0 {
		fmt.Fprintln(out, pal.Error("КОНФЛИКТ (маркеры в файлах, требуется ручное разрешение):"))
		for _, c := range r.Conflicts {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}
	if len(r.LocalDeviations) > 0 {
		fmt.Fprintln(out, pal.Warn("локальные отклонения (сделано не по шаблону, work↔baseline):"))
		for _, d := range r.LocalDeviations {
			fmt.Fprintf(out, "  %s (%s)\n", d.Path, deltaStr(pal, d))
			if verbose {
				fmt.Fprint(out, indent(r.diffs[d.Path]))
			}
		}
		if !verbose {
			fmt.Fprintln(out, pal.Muted("  (--verbose — показать унифицированный diff)"))
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintln(out, pal.Warn("предупреждение: ")+w)
	}
}

// deltaStr форматирует «+A -R строк» палитрой.
func deltaStr(pal ui.Palette, d FileDelta) string {
	return fmt.Sprintf("%s %s", pal.Success(fmt.Sprintf("+%d", d.Added)), pal.Warn(fmt.Sprintf("-%d", d.Removed)))
}

// lineDelta считает число добавленных/удалённых строк между oldB и newB через LCS.
func lineDelta(oldB, newB []byte) (added, removed int) {
	a := splitLines(oldB)
	b := splitLines(newB)
	common := len(lcsPairs(a, b))
	return len(b) - common, len(a) - common
}

// unifiedDiff строит компактный построчный diff oldB→newB на базе LCS: строки
// только в oldB помечаются «-», только в newB — «+», общие — пробелом.
func unifiedDiff(oldB, newB []byte) string {
	a := splitLines(oldB)
	b := splitLines(newB)
	pairs := lcsPairs(a, b)

	var sb []byte
	emit := func(prefix byte, lines []string) {
		for _, ln := range lines {
			sb = append(sb, prefix)
			sb = append(sb, ln...)
			sb = append(sb, '\n')
		}
	}

	ai, bi := 0, 0
	for _, p := range pairs {
		emit('-', a[ai:p.a])
		emit('+', b[bi:p.b])
		emit(' ', a[p.a:p.a+1])
		ai, bi = p.a+1, p.b+1
	}
	emit('-', a[ai:])
	emit('+', b[bi:])
	return string(sb)
}

// indent добавляет отступ к каждой строке блока diff.
func indent(s string) string {
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s)+8)
	lineStart := true
	for i := 0; i < len(s); i++ {
		if lineStart {
			out = append(out, ' ', ' ', ' ', ' ')
			lineStart = false
		}
		out = append(out, s[i])
		if s[i] == '\n' {
			lineStart = true
		}
	}
	return string(out)
}
