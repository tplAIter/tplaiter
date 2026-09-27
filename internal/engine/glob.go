package engine

import (
	"regexp"
	"strings"
)

// globSet — набор glob-паттернов, скомпилированных в регулярные выражения.
// Поддерживает синтаксис files-глобов манифеста: `*` (в пределах
// сегмента), `**` (через сегменты, включая ноль сегментов), `?` (один символ,
// кроме `/`). Перенос go-template без изменений — язык глобов не меняется.
type globSet struct {
	res []*regexp.Regexp
}

// newGlobSet компилирует список глобов в набор для сопоставления путей.
func newGlobSet(globs []string) *globSet {
	gs := &globSet{res: make([]*regexp.Regexp, 0, len(globs))}
	for _, g := range globs {
		gs.res = append(gs.res, globToRegexp(g))
	}
	return gs
}

// matchAny сообщает, соответствует ли slash-путь хотя бы одному глобу набора.
func (g *globSet) matchAny(path string) bool {
	for _, re := range g.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegexp транслирует glob (с поддержкой `**` как отдельного сегмента
// пути — ноль или более сегментов, в т.ч. на границах глоба, например
// `**/dashboards/*.json` соответствует и `dashboards/app.json` без ведущих
// каталогов) в якорное регулярное выражение. Путь трактуется как
// slash-разделённый (path.Clean-семантика).
//
// `**`, встретившийся НЕ как отдельный сегмент (`**` окружён `/` или это весь
// глоб), не имеет специального смысла кросс-сегментного джокера — такое
// использование не входит в язык глобов манифеста и трактуется
// как последовательность одиночных `*`.
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

// writeDoubleStarSegment дописывает регулярное выражение для сегмента `**` на
// позиции i из total сегментов глоба: ведущий — ноль или более каталогов без
// требования разделителя перед собой; срединный — ноль или более каталогов
// между обязательными разделителями соседей; хвостовой — сохраняет исходное
// (перенесённое из go-template) поведение: обязательный разделитель перед
// собой, затем произвольный остаток (включая пустой).
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

// segmentToRegexp транслирует один сегмент пути (без `/`) в regexp:
// `*` — произвольное число символов кроме `/`, `?` — один символ кроме `/`.
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
