package engine

import (
	"regexp"
	"strings"
)

// globSet is a set of glob patterns compiled to regular expressions. It
// supports the manifest files-glob syntax: `*` within a segment, `**` across
// segments (including zero segments), and `?` for one character other than `/`.
// This is an unchanged go-template port; the glob language is unchanged.
type globSet struct {
	res []*regexp.Regexp
}

// newGlobSet compiles a list of globs into a path-matching set.
func newGlobSet(globs []string) *globSet {
	gs := &globSet{res: make([]*regexp.Regexp, 0, len(globs))}
	for _, g := range globs {
		gs.res = append(gs.res, globToRegexp(g))
	}
	return gs
}

// matchAny reports whether a slash-separated path matches at least one set glob.
func (g *globSet) matchAny(path string) bool {
	for _, re := range g.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegexp translates a glob (supporting `**` as a separate path segment,
// meaning zero or more segments, including at glob boundaries; for example,
// `**/dashboards/*.json` also matches `dashboards/app.json` without a leading
// directory) into an anchored regular expression. Paths use slash separators
// (path.Clean semantics).
//
// `**` appearing other than as a separate segment (`**` surrounded by `/` or
// the entire glob) has no cross-segment wildcard meaning. Such usage is outside
// the manifest glob language and is treated as a sequence of single `*`s.
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

// writeDoubleStarSegment appends the regular expression for a `**` segment at
// position i of total glob segments: a leading segment matches zero or more
// directories without requiring a preceding separator; a middle segment matches
// zero or more directories between required neighboring separators; a trailing
// segment preserves the original go-template behavior: a required preceding
// separator followed by any remainder (including empty).
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

// segmentToRegexp translates one path segment (without `/`) into a regexp:
// `*` matches any number of characters other than `/`, and `?` matches one.
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
