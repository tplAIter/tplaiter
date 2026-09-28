package contribute

import (
	"regexp"
	"strings"
)

// Matching slash-separated paths against glob patterns. Duplicated from
// internal/engine/glob.go (globToRegexp/segmentToRegexp/writeDoubleStarSegment).
// Additive, exactly as in internal/stats/glob.go: those functions are not
// exported there, and expanding engine for one matcher is undesirable.
// The glob language is the same: `*` within a segment, `**` as a separate
// segment (zero or more directories), `?` as one character except `/`. The
// matcher serves upgrade for selecting --files extras and determining whether
// a file belongs to a conditional vertical (manifest files rules).

// globMatcher — set of globs compiled into regular expressions.
type globMatcher struct {
	res []*regexp.Regexp
}

// newGlobMatcher compiles a list of globs into a matcher.
func newGlobMatcher(globs []string) *globMatcher {
	m := &globMatcher{res: make([]*regexp.Regexp, 0, len(globs))}
	for _, g := range globs {
		m.res = append(m.res, globToRegexp(g))
	}
	return m
}

// match reports whether a slash-separated path matches at least one glob.
func (m *globMatcher) match(path string) bool {
	for _, re := range m.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegexp translates a glob (with `**` as a separate segment representing
// zero or more directories) into an anchored regular expression. Copy of engine.globToRegexp.
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

// writeDoubleStarSegment appends the regexp for a `**` segment. Copy of
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

// segmentToRegexp translates one path segment into a regexp. Copy of
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
