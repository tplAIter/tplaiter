package gen

import (
	"fmt"
	"strings"
)

// insertBeforeAnchor inserts block before the first line containing anchor
// (for example, "// CODEGEN:WIRING"). Indentation/formatting are not normalized
// here; the insertion-template author owns its indentation (see gen.go's package
// comment about the gofumpt post-step). It returns an error when anchor is absent.
func insertBeforeAnchor(content, anchor, block string) (string, error) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if !strings.Contains(line, anchor) {
			continue
		}
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i]...)
		out = append(out, strings.TrimRight(block, "\n"))
		out = append(out, lines[i:]...)
		return strings.Join(out, "\n"), nil
	}
	return "", fmt.Errorf("gen: якорь %q не найден", anchor)
}
