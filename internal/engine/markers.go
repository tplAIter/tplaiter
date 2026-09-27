package engine

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// markerPrefix is the common prefix of all in-file markers. A marker is found
// as a substring of the line, regardless of the surrounding comment style
// (//, #, <!-- -->, /* */, ;).
const markerPrefix = "tplater:"

// Marker keywords immediately following [markerPrefix].
const (
	markerKwIfInverse = "if!"
	markerKwIf        = "if"
	markerKwBegin     = "begin"
	markerKwEnd       = "end"
)

// commentPrefixes are known comment-opening sequences. For a trailing
// tplater:if, the “comment start” is the last occurrence of any of them before
// the marker; when none is present, a generic fallback is used
// (see [commentStartBefore]).
var commentPrefixes = []string{"//", "#", "<!--", "/*", ";"}

// commentSuffixes are closing sequences for comment styles. They are excluded
// from trailing or begin-marker condition text when the remainder ends with
// one (`<!-- tplater:if x=y -->`, `/* tplater:end */`).
var commentSuffixes = []string{"-->", "*/"}

// markerKind is the recognized marker kind on a file line.
type markerKind int

const (
	markerKindIf markerKind = iota
	markerKindIfInverse
	markerKindBegin
	markerKindEnd
	markerKindUnknown
)

// markerMatch is the result of parsing one line for a marker: idx is the index
// where "tplater:" starts, and argIdx is the index where text AFTER the
// keyword starts (the argument/condition for if and begin; unused for end and
// unknown).
type markerMatch struct {
	kind   markerKind
	idx    int
	argIdx int
}

// findMarker finds the first [markerPrefix] occurrence in a line and classifies
// it by keyword. The keyword must end at a non-identifier boundary (or the end
// of the line), so "tplater:iff" and "tplater:endpoint" are reported as
// [markerKindUnknown] rather than confused with known markers (typo protection).
func findMarker(line string) (markerMatch, bool) {
	idx := strings.Index(line, markerPrefix)
	if idx < 0 {
		return markerMatch{}, false
	}
	after := line[idx+len(markerPrefix):]

	// Check if! before if; otherwise if would incorrectly match the if! prefix
	// (see matchesKeyword: "!" is a boundary character, so if would also match
	// "if!..." if checked first).
	switch {
	case matchesKeyword(after, markerKwIfInverse):
		return markerMatch{kind: markerKindIfInverse, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwIfInverse)}, true
	case matchesKeyword(after, markerKwIf):
		return markerMatch{kind: markerKindIf, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwIf)}, true
	case matchesKeyword(after, markerKwBegin):
		return markerMatch{kind: markerKindBegin, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwBegin)}, true
	case matchesKeyword(after, markerKwEnd):
		return markerMatch{kind: markerKindEnd, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwEnd)}, true
	default:
		return markerMatch{kind: markerKindUnknown, idx: idx}, true
	}
}

// matchesKeyword reports whether after starts with keyword followed by a
// boundary (the end of the line or a non-identifier character).
func matchesKeyword(after, keyword string) bool {
	if !strings.HasPrefix(after, keyword) {
		return false
	}
	if len(after) == len(keyword) {
		return true
	}
	return isIdentBoundary(after[len(keyword)])
}

// isIdentBoundary reports whether byte b cannot be part of an identifier
// (letter, digit, or underscore); it separates a marker keyword from accidental
// continuation (typo protection).
func isIdentBoundary(b byte) bool {
	switch {
	case b == '_':
		return false
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return false
	default:
		return true
	}
}

// commentStartBefore finds the index of the “comment sequence start” before a
// marker at markerIdx: the last occurrence of any [commentPrefixes] in
// line[:markerIdx]. If no prefix is found, the generic fallback is the marker
// index (after TrimRight, this is equivalent to cutting at the last whitespace
// boundary before it).
func commentStartBefore(line string, markerIdx int) int {
	head := line[:markerIdx]
	best := -1
	for _, p := range commentPrefixes {
		if i := strings.LastIndex(head, p); i > best {
			best = i
		}
	}
	if best >= 0 {
		return best
	}
	return markerIdx
}

// extractMarkerArg extracts a marker argument (the if/begin condition) from the
// remainder after the keyword: it trims spaces and removes a trailing comment
// style suffix ([commentSuffixes]) so that it does not enter the condition text
// (`<!-- tplater:if x=y -->`).
func extractMarkerArg(rest string) string {
	s := strings.TrimSpace(rest)
	for _, suf := range commentSuffixes {
		if strings.HasSuffix(s, suf) {
			s = strings.TrimSpace(strings.TrimSuffix(s, suf))
			break
		}
	}
	return s
}

// evalConditionExpr parses and evaluates the marker condition from §3.2 against values.
func evalConditionExpr(expr string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(expr)
	if err != nil {
		return false, err
	}
	ok, err := settings.Eval(cond, values)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// markerFrame is an open tplater:begin in the nesting stack.
type markerFrame struct {
	line       int    // begin line number in the source file (for an unpaired error)
	expr       string // original condition text (for an error message)
	prevActive bool   // active before this begin; restored at end
}

// processMarkers handles in-file tplater:if / tplater:if! / tplater:begin /
// tplater:end markers in file content AFTER text rendering or byte copying;
// see the engine.go (renderFile) integration and the  behavior description
// for the integration point and copyWithoutRender exclusion.
//
// path is the logical file path in the project tree, used only in error
// messages. values is the template's [settings.Resolved.ActiveValues].
//
// Errors (all fatal, with path:line): unmatched tplater:begin, tplater:end
// without tplater:begin, syntactically invalid conditions or conditions
// referencing unknown groups, and unknown tplater markers (typo protection,
// such as tplater:iff). Nested blocks are supported through [markerFrame].
func processMarkers(path string, data []byte, values settings.Values) ([]byte, error) {
	if !bytes.Contains(data, []byte(markerPrefix)) {
		return data, nil // fast path: the file has no markers at all
	}

	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))

	var stack []markerFrame
	active := true

	for i, line := range lines {
		lineNo := i + 1
		m, found := findMarker(line)
		if !found {
			if active {
				out = append(out, line)
			}
			continue
		}

		switch m.kind {
		case markerKindUnknown:
			return nil, fmt.Errorf("engine: %s:%d: неизвестный tplater-маркер в строке %q", path, lineNo, line)

		case markerKindBegin:
			expr := extractMarkerArg(line[m.argIdx:])
			ok, err := evalConditionExpr(expr, values)
			if err != nil {
				return nil, fmt.Errorf("engine: %s:%d: tplater:begin %s: %w", path, lineNo, expr, err)
			}
			stack = append(stack, markerFrame{line: lineNo, expr: expr, prevActive: active})
			active = active && ok
			// The begin line itself is always removed from the output.

		case markerKindEnd:
			if len(stack) == 0 {
				return nil, fmt.Errorf("engine: %s:%d: tplater:end без соответствующего tplater:begin", path, lineNo)
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			active = top.prevActive
			// The end line itself is always removed from the output.

		case markerKindIf, markerKindIfInverse:
			expr := extractMarkerArg(line[m.argIdx:])
			ok, err := evalConditionExpr(expr, values)
			if err != nil {
				return nil, fmt.Errorf("engine: %s:%d: tplater:if %s: %w", path, lineNo, expr, err)
			}
			if m.kind == markerKindIfInverse {
				ok = !ok
			}
			// active takes precedence over a trailing marker: a line inside a disabled
			// tplater:begin block is removed in full regardless of its own condition
			// (the condition was still checked above, so syntax and group are valid in
			// dead code as required by lint).
			if !active || !ok {
				continue
			}
			cut := commentStartBefore(line, m.idx)
			out = append(out, strings.TrimRight(line[:cut], " \t"))
		}
	}

	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return nil, fmt.Errorf("engine: %s:%d: непарный tplater:begin %s (нет соответствующего tplater:end)", path, top.line, top.expr)
	}

	result := []byte(strings.Join(out, "\n"))
	if bytes.Contains(result, []byte(markerPrefix)) {
		// Safety net: control should never reach this point; every marker above was
		// either handled or returned an error. If "tplater:" remains in the output,
		// it is a marker-processing bug, not a template-author typo (already caught
		// as markerKindUnknown).
		return nil, fmt.Errorf("engine: %s: маркер tplater: остался в обработанном выводе (внутренняя ошибка)", path)
	}
	return result, nil
}
