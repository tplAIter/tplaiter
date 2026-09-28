package stats

import (
	"regexp"
	"strings"
)

// Path matching for the manifest's copyWithoutRender glob patterns. This is an
// additive copy of internal/engine/glob.go (globToRegexp/segmentToRegexp/
// writeDoubleStarSegment), whose helpers are not exported. The glob language is
// the same: `*` within a segment, `**` as a standalone segment (zero or more
// directories), and `?` for one character other than `/`. Consistency with
// engine matters: stats must classify exactly the files copied without rendering
// as manual-only.

// globMatcher is a set of globs compiled into regular expressions.
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

// match reports whether a slash path matches at least one glob.
func (m *globMatcher) match(path string) bool {
	for _, re := range m.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegexp translates a glob (with `**` as a standalone segment matching
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

// segmentToRegexp translates one path segment to a regexp. Copy of
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
