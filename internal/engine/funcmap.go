// Package engine implements the manifest-model template rendering engine
// ( §3.1, §4). It is a port with a different metadata source:
// instead of gotmpl-specific template.json + gotmpl.json, it uses
// *manifest.Template (the manifest engine section) and resolved settings
// ([settings.Resolved]).
//
// The file-tree source is any fs.FS (in production, a template repository on
// disk/from a git worktree; in tests, an os.DirFS fixture). Its layout is
// <Template.Engine.Root>/** ("files/" by default). *.tmpl contents are rendered
// through text/template with a custom FuncMap (without sprig, as required by
// go-template §2.4); file names use string placeholder substitution
// (__slug__, __module__) and support conditional segments __if_<group>__ /
// __if_<group>=<value>__. The result is deterministic: Baseline (sha256 of
// each file plus the context hash) is stable for identical input.
package engine

import (
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/tplAIter/tplaiter/internal/settings"
)

// tmplSuffix is the suffix of files whose contents are rendered through
// text/template.
const tmplSuffix = ".tmpl"

// StaticFuncMap returns string-transforming functions independent of the
// resolved settings for a particular render (the go-template port is kept
// unchanged by design: a custom implementation without sprig).
func StaticFuncMap() template.FuncMap {
	return template.FuncMap{
		"slug":   Slugify,
		"snake":  Snake,
		"camel":  Camel,
		"pascal": Pascal,
		"kebab":  Kebab,
		"upper":  strings.ToUpper,
		"lower":  strings.ToLower,
		"quote":  strconv.Quote,
		"split":  splitOn,
	}
}

// splitOn splits s by separator sep into []string (a strings.Split wrapper
// with "string, separator" argument order, convenient for the pipeline
// `{{ .Name.Raw | split "." }}`). Generators use it to decompose compound
// identifiers (for example, "payments.DebitAccount" → service + activity):
// text/template has no built-in split.
func splitOn(sep, s string) []string { return strings.Split(s, sep) }

// FuncMap returns the complete render function set for a settings view:
// [StaticFuncMap] plus `is`/`has` helpers, wrappers around
// [settings.View.Is]/[settings.View.Has] — {{ if is "database" "postgres" }},
// {{ if has "brokers" "kafka" }}.
func FuncMap(view settings.View) template.FuncMap {
	fm := StaticFuncMap()
	fm["is"] = view.Is
	fm["has"] = view.Has
	return fm
}

// splitWords splits an arbitrary string into lowercase words at separators
// (_-. /), camelCase boundaries (aB), and acronym boundaries
// (HTTPServer → http, server). It is the basis for all case conversions (the
// go-template port is unchanged).
func splitWords(s string) []string {
	runes := []rune(s)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0:0]
		}
	}
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.' || r == '/':
			flush()
		case unicode.IsUpper(r):
			if i > 0 {
				prev := runes[i-1]
				var next rune
				if i+1 < len(runes) {
					next = runes[i+1]
				}
				switch {
				case unicode.IsLower(prev) || unicode.IsDigit(prev):
					flush()
				case unicode.IsUpper(prev) && unicode.IsLower(next):
					flush()
				}
			}
			cur = append(cur, unicode.ToLower(r))
		default:
			cur = append(cur, unicode.ToLower(r))
		}
	}
	flush()
	return words
}

func upperFirst(w string) string {
	if w == "" {
		return w
	}
	r := []rune(w)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// Snake converts a string to snake_case.
func Snake(s string) string { return strings.Join(splitWords(s), "_") }

// Kebab converts a string to kebab-case.
func Kebab(s string) string { return strings.Join(splitWords(s), "-") }

// Pascal converts a string to PascalCase.
func Pascal(s string) string {
	words := splitWords(s)
	for i, w := range words {
		words[i] = upperFirst(w)
	}
	return strings.Join(words, "")
}

// Camel converts a string to camelCase.
func Camel(s string) string {
	words := splitWords(s)
	for i, w := range words {
		if i == 0 {
			continue
		}
		words[i] = upperFirst(w)
	}
	return strings.Join(words, "")
}

// Slugify converts a name to a slug in the ^[a-z][a-z0-9_]*$ (snake_case)
// format. The caller in the project-creation command checks final validity,
// such as ensuring the slug does not begin with a digit.
func Slugify(s string) string { return Snake(s) }
