// Package update upgrades a generated project to a new template version
// (`tplaiter update`) using a cruft 3-way model.
//
// The core is a line-based diff3 merge: base (clean render of the pinned
// template), ours (project work tree), and theirs (clean target render).
// Non-overlapping edits merge automatically; overlaps produce
// <<<<<<< ours / ======= / >>>>>>> template markers. The implementation is local:
// compact LCS plus stitching at common anchors avoids an external dependency.
// The mechanism was adapted from go-template/cli/gotmpl/internal/update for the
// tplaiter manifest model (two git-ref renders instead of version/features).
package update

import "strings"

// Conflict markers. The format is compatible with git and ScanConflicts.
const (
	markerOurs      = "<<<<<<< ours"
	markerSeparator = "======="
	markerTheirs    = ">>>>>>> template"
)

// pair is a matched index pair in base and another sequence.
type pair struct{ a, b int }

// lcsPairs returns longest-common-subsequence index pairs for a and b in
// increasing order on both coordinates. O(n*m) time and memory is acceptable for template files.
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

// baseAlign maps baseIdx to otherIdx using LCS(base, other). Monotonicity in
// baseIdx (an LCS property) keeps merge anchors consistent.
func baseAlign(base, other []string) map[int]int {
	pairs := lcsPairs(base, other)
	m := make(map[int]int, len(pairs))
	for _, p := range pairs {
		m[p.a] = p.b
	}
	return m
}

// diff3Merge performs a line-based three-way merge.
//
// It returns merged lines and a conflict flag. Anchors are base lines matching
// both ours and theirs; regions between adjacent anchors are decided independently:
//   - ours==theirs (same edit) -> ours;
//   - ours==base (only theirs changed) -> theirs;
//   - theirs==base (only ours changed) -> ours;
//   - otherwise -> conflict markers.
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

// equalLines compares two line slices element by element.
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

// splitLines splits content so joinLines reverses it byte-for-byte. Empty content
// -> nil (join(nil) == ""), keeping empty and one-line files distinct. A final
// \n is preserved as a trailing "".
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	return strings.Split(string(content), "\n")
}

// joinLines assembles lines back into byte content.
func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n"))
}

// merge3 is a convenience wrapper around diff3Merge for byte inputs.
func merge3(base, ours, theirs []byte) (merged []byte, conflict bool) {
	lines, c := diff3Merge(splitLines(ours), splitLines(base), splitLines(theirs))
	return joinLines(lines), c
}
