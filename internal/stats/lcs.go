package stats

import "strings"

// Core of the line-based drift metric. LCS is copied additively from
// internal/update/diff3.go (lcsPairs/splitLines): those functions are not
// exported and stats needs only LCS length (for +/- counts and changed-line
// percentage), so compact DP length is used instead of reconstructing pairs.
// splitLines semantics match update.splitLines byte-for-byte so the metric agrees
// with what update actually merges.

// splitLines splits content into lines. Empty content -> nil (empty and one-line
// files remain distinguishable). Matches internal/update.splitLines.
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	return strings.Split(string(content), "\n")
}

// lcsLen returns the longest common subsequence length for lines a and b.
// O(n*m) time and memory is acceptable for template files (the same bound as
// lcsPairs in internal/update/diff3.go).
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

// lineMetric compares reference (base) and work content by line and returns:
// added, lines absent from the reference; removed, reference lines absent from
// work; and percent, (added+removed)/max(len(base),len(work))*100. Two empty
// files have zero drift.
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
