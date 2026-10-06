package semanticpreview

import (
	"fmt"
	"strings"
)

const maxDiffLines = 8192
const maxDiffWork = 2_000_000

func diffLines(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// unifiedDiff returns the complete deterministic file hunk. It refuses before
// bounded LCS allocation; successful output never drops an image or diff tail.
func unifiedDiff(p string, before, after []byte) (string, error) {
	a, b := diffLines(before), diffLines(after)
	if len(a) > maxDiffLines || len(b) > maxDiffLines || len(a)*len(b) > maxDiffWork {
		return "", ErrBudget
	}
	if string(before) == string(after) {
		return "", nil
	}
	cols := len(b) + 1
	dp := make([]uint16, (len(a)+1)*cols)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i*cols+j] = dp[(i+1)*cols+j+1] + 1
			} else {
				dp[i*cols+j] = max(dp[(i+1)*cols+j], dp[i*cols+j+1])
			}
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n@@ -%d,%d +%d,%d @@\n", p, p, min(1, len(a)), len(a), min(1, len(b)), len(b))
	line := func(prefix byte, s string) {
		out.WriteByte(prefix)
		out.WriteString(s)
		if !strings.HasSuffix(s, "\n") {
			out.WriteString("\n\\ No newline at end of file\n")
		}
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if i < len(a) && j < len(b) && a[i] == b[j] {
			line(' ', a[i])
			i++
			j++
		} else if i < len(a) && (j == len(b) || dp[(i+1)*cols+j] >= dp[i*cols+j+1]) {
			line('-', a[i])
			i++
		} else {
			line('+', b[j])
			j++
		}
	}
	return out.String(), nil
}
