// Package update реализует обновление сгенерированного проекта на новую версию
// шаблона (`tplater update`) по 3-way-модели cruft.
//
// Ядро — построчный diff3-merge (см. diff3.go): base (общий предок — чистый
// рендер зафиксированной версии шаблона), ours (рабочее дерево проекта), theirs
// (чистый рендер целевой версии). Непересекающиеся правки объединяются
// автоматически; пересекающиеся дают конфликт-маркеры
// <<<<<<< ours / ======= / >>>>>>> template. Реализация diff3 собственная (без
// внешней зависимости): алгоритм компактен (LCS + сшивка по общим якорям), а
// добавление внешнего пакета ради ~150 строк расширяет поверхность зависимостей.
// Механика перенесена из go-template/cli/gotmpl/internal/update и обобщена на
// манифест-модель tplater (рендер двух git-ref-ов вместо version/features).
package update

import "strings"

// Маркеры конфликта. Формат совместим с git и сканером ScanConflicts.
const (
	markerOurs      = "<<<<<<< ours"
	markerSeparator = "======="
	markerTheirs    = ">>>>>>> template"
)

// pair — сопоставленная пара индексов (в base и в другой последовательности).
type pair struct{ a, b int }

// lcsPairs возвращает пары индексов наибольшей общей подпоследовательности a и b
// в возрастающем порядке по обеим координатам. O(n*m) по времени и памяти —
// приемлемо для файлов шаблона.
func lcsPairs(a, b []string) []pair {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return nil
	}
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out []pair
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case a[i] == b[j]:
			out = append(out, pair{i, j})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return out
}

// baseAlign строит отображение baseIdx→otherIdx по LCS(base, other). Монотонно
// по baseIdx (свойство LCS), что гарантирует согласованность якорей в merge.
func baseAlign(base, other []string) map[int]int {
	pairs := lcsPairs(base, other)
	m := make(map[int]int, len(pairs))
	for _, p := range pairs {
		m[p.a] = p.b
	}
	return m
}

// diff3Merge выполняет построчное трёхстороннее слияние.
//
// Возвращает объединённые строки и признак конфликта. Якоря — строки base,
// совпавшие И с ours, И с theirs; между соседними якорями лежат «регионы», для
// которых решение принимается независимо:
//   - ours==theirs (одинаковая правка) → берём ours;
//   - ours==base (изменил только theirs) → берём theirs;
//   - theirs==base (изменил только ours) → берём ours;
//   - иначе → конфликт с маркерами.
func diff3Merge(ours, base, theirs []string) (merged []string, conflict bool) {
	ao := baseAlign(base, ours)   // baseIdx -> oursIdx
	at := baseAlign(base, theirs) // baseIdx -> theirsIdx

	var anchors []int
	for i := 0; i < len(base); i++ {
		if _, ok := ao[i]; !ok {
			continue
		}
		if _, ok := at[i]; ok {
			anchors = append(anchors, i)
		}
	}

	out := make([]string, 0, len(ours))
	emitRegion := func(oStart, oEnd, tStart, tEnd, bStart, bEnd int) {
		oursSeg := ours[oStart:oEnd]
		theirsSeg := theirs[tStart:tEnd]
		baseSeg := base[bStart:bEnd]
		switch {
		case equalLines(oursSeg, theirsSeg):
			out = append(out, oursSeg...)
		case equalLines(oursSeg, baseSeg):
			out = append(out, theirsSeg...)
		case equalLines(theirsSeg, baseSeg):
			out = append(out, oursSeg...)
		default:
			conflict = true
			out = append(out, markerOurs)
			out = append(out, oursSeg...)
			out = append(out, markerSeparator)
			out = append(out, theirsSeg...)
			out = append(out, markerTheirs)
		}
	}

	bPrev, oPrev, tPrev := -1, -1, -1
	for _, bi := range anchors {
		oi, ti := ao[bi], at[bi]
		emitRegion(oPrev+1, oi, tPrev+1, ti, bPrev+1, bi)
		out = append(out, base[bi])
		bPrev, oPrev, tPrev = bi, oi, ti
	}
	emitRegion(oPrev+1, len(ours), tPrev+1, len(theirs), bPrev+1, len(base))
	return out, conflict
}

// equalLines сравнивает два среза строк поэлементно.
func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// splitLines разбивает содержимое на строки так, что joinLines обращает split
// побайтово. Пустое содержимое → nil (join(nil) == ""), поэтому пустой и
// однострочный файлы различимы. Финальный \n сохраняется как хвостовой "".
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	return strings.Split(string(content), "\n")
}

// joinLines собирает строки обратно в байтовое содержимое.
func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n"))
}

// merge3 — удобная обёртка над diff3Merge для байтовых входов.
func merge3(base, ours, theirs []byte) (merged []byte, conflict bool) {
	lines, c := diff3Merge(splitLines(ours), splitLines(base), splitLines(theirs))
	return joinLines(lines), c
}
