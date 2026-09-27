package stats

import (
	"regexp"
	"strings"
)

// Сопоставление путей с glob-паттернами copyWithoutRender манифеста.
// Продублировано из internal/engine/glob.go (globToRegexp/segmentToRegexp/
// writeDoubleStarSegment) АДДИТИВНО: там эти функции не экспортированы, а
// пакет engine расширять ради одного матчера не хочется. Язык глобов —
// тот же: `*` в пределах сегмента, `**` как отдельный сегмент
// (ноль или более каталогов), `?` — один символ кроме `/`. Согласованность с
// engine важна: stats обязан относить к manual-only ровно те файлы, что движок
// копирует без рендера.

// globMatcher — набор глобов, скомпилированных в регулярные выражения.
type globMatcher struct {
	res []*regexp.Regexp
}

// newGlobMatcher компилирует список глобов в матчер.
func newGlobMatcher(globs []string) *globMatcher {
	m := &globMatcher{res: make([]*regexp.Regexp, 0, len(globs))}
	for _, g := range globs {
		m.res = append(m.res, globToRegexp(g))
	}
	return m
}

// match сообщает, соответствует ли slash-путь хотя бы одному глобу.
func (m *globMatcher) match(path string) bool {
	for _, re := range m.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegexp транслирует glob (с `**` как отдельным сегментом — ноль или
// более каталогов) в якорное регулярное выражение. Копия engine.globToRegexp.
func globToRegexp(glob string) *regexp.Regexp {
	segs := strings.Split(glob, "/")
	var b strings.Builder
	b.WriteString("^")
	needSlash := false
	for i, seg := range segs {
		if seg == "**" && len(segs) > 1 {
			writeDoubleStarSegment(&b, i, len(segs), needSlash)
			needSlash = false
			continue
		}
		if needSlash {
			b.WriteString("/")
		}
		b.WriteString(segmentToRegexp(seg))
		needSlash = true
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// writeDoubleStarSegment дописывает regexp для сегмента `**`. Копия
// engine.writeDoubleStarSegment.
func writeDoubleStarSegment(b *strings.Builder, i, total int, needSlash bool) {
	if i == 0 {
		b.WriteString("(?:.*/)?")
		return
	}
	if needSlash {
		b.WriteString("/")
	}
	if i == total-1 {
		b.WriteString(".*")
		return
	}
	b.WriteString("(?:.*/)?")
}

// segmentToRegexp транслирует один сегмент пути в regexp. Копия
// engine.segmentToRegexp.
func segmentToRegexp(seg string) string {
	var b strings.Builder
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch c {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
