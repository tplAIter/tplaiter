package stats

import "strings"

// Ядро построчной метрики дрейфа. LCS продублирован из
// internal/update/diff3.go (lcsPairs/splitLines) АДДИТИВНО: там эти функции
// не экспортированы, а реализация  не должна редактировать пакет update (его
// параллельно рефакторит реализация ). Здесь нужна только длина LCS (для счётчиков
// ± и процента изменённых строк), поэтому вместо восстановления пар считается
// компактная DP-длина. Семантика splitLines совпадает с update.splitLines
// побайтово, чтобы метрика была согласована с тем, что реально мержит update.

// splitLines разбивает содержимое на строки. Пустое содержимое → nil (пустой и
// однострочный файлы различимы). Совпадает с internal/update.splitLines.
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	return strings.Split(string(content), "\n")
}

// lcsLen возвращает длину наибольшей общей подпоследовательности строк a и b.
// O(n*m) по времени и памяти — приемлемо для файлов шаблона (та же оценка, что
// у lcsPairs в internal/update/diff3.go).
func lcsLen(a, b []string) int {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return 0
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
	return dp[0][0]
}

// lineMetric сравнивает эталонное (base) и рабочее (work) содержимое построчно и
// возвращает: added — строки, которых нет в эталоне (добавлены пользователем),
// removed — строки эталона, отсутствующие в work (удалены), percent —
// (added+removed)/max(len(base),len(work))*100 ( метрика % изменённых
// строк). Оба пустых файла → нулевой дрейф.
func lineMetric(base, work []byte) (added, removed int, percent float64) {
	bLines := splitLines(base)
	wLines := splitLines(work)
	common := lcsLen(bLines, wLines)
	removed = len(bLines) - common
	added = len(wLines) - common
	denom := len(bLines)
	if len(wLines) > denom {
		denom = len(wLines)
	}
	if denom == 0 {
		return 0, 0, 0
	}
	percent = float64(added+removed) / float64(denom) * 100
	return added, removed, percent
}
