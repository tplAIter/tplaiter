package contribute

import (
	"bytes"
	"path"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// minSubstLen — minimum project-value length below which reverse substitution
// is not performed (implementation detail): short slugs such as "app"/"api"
// occur too often accidentally in code, and replacing them with a placeholder
// would corrupt the content. Module (the Go path) is always longer and is always replaced.
const minSubstLen = 4

// reviewMarker — text inserted by upgrade into the header of a file belonging
// to a conditional vertical (files glob option). A complete reverse
// transformation of conditional blocks is algorithmically unreliable, so the
// template reviewer handles it explicitly.
const reviewMarker = "TPLATER-REVIEW: файл принадлежит условной вертикали"

// substitution — one reverse substitution: literal project value → go-template placeholder.
type substitution struct {
	value       string
	placeholder string
}

// buildSubstitutions builds an ordered list of reverse substitutions from the
// project coordinates. They are applied in descending value length, so more
// specific/longer occurrences (especially Module, the Go path containing Slug)
// are replaced first and are not damaged by shorter replacements. Equal values
// are deduplicated: when Slug==Name==Snake (common), one substitution remains
// with the most canonical placeholder (Slug takes priority over Snake/Name).
func buildSubstitutions(p manifest.ProjectInfo) []substitution {
	slug := p.Slug
	// Candidates in placeholder-priority order for value deduplication.
	// Module first: it is the longest and most specific value (the Go path).
	candidates := []substitution{
		{p.Module, "{{ .Project.Module }}"},
		{slug, "{{ .Project.Slug }}"},
		{engine.Pascal(slug), "{{ .Project.Pascal }}"},
		{engine.Camel(slug), "{{ .Project.Camel }}"},
		{engine.Kebab(slug), "{{ .Project.Kebab }}"},
		{engine.Snake(slug), "{{ .Project.Snake }}"},
		{p.Name, "{{ .Project.Name }}"},
		{p.System, "{{ .Project.System }}"},
		{p.Domain, "{{ .Project.Domain }}"},
	}

	seen := make(map[string]struct{}, len(candidates))
	subs := make([]substitution, 0, len(candidates))
	for _, c := range candidates {
		if len(c.value) < minSubstLen {
			continue // value too short/empty — do not replace (noise).
		}
		if _, dup := seen[c.value]; dup {
			continue // deduplication: value is already covered by a higher-priority placeholder.
		}
		seen[c.value] = struct{}{}
		subs = append(subs, c)
	}

	// Apply in descending value length: long values (Module) before short ones,
	// otherwise replacing the short Slug would split a Module occurrence.
	sort.SliceStable(subs, func(i, j int) bool {
		return len(subs[i].value) > len(subs[j].value)
	})
	return subs
}

// derender applies reverse substitutions to work-file content: for each
// substitution, it replaces all literal occurrences of value with placeholder.
// Returns the result and whether at least one replacement occurred (needed for
// the "extra file -> .tmpl only if placeholders appeared" heuristic).
func derender(content []byte, subs []substitution) (out []byte, changed bool) {
	out = content
	for _, s := range subs {
		vb := []byte(s.value)
		if !bytes.Contains(out, vb) {
			continue
		}
		out = bytes.ReplaceAll(out, vb, []byte(s.placeholder))
		changed = true
	}
	return out, changed
}

// commentStyle returns opening/closing fragments for a line comment in
// logicalPath (based on extension; the .tmpl suffix is removed). ok=false for
// formats without a known comment style (binary/JSON, etc.); for those files,
// the review marker goes into the MR description rather than the file body.
func commentStyle(logicalPath string) (open, closeTag string, ok bool) {
	name := strings.TrimSuffix(logicalPath, ".tmpl")
	base := path.Base(name)
	ext := strings.ToLower(path.Ext(name))

	switch ext {
	case ".go", ".java", ".kt", ".ts", ".tsx", ".js", ".jsx", ".c", ".h",
		".cc", ".cpp", ".hpp", ".rs", ".scala", ".swift", ".proto", ".groovy":
		return "// ", "", true
	case ".yaml", ".yml", ".sh", ".bash", ".zsh", ".py", ".rb", ".toml",
		".ini", ".conf", ".cfg", ".env", ".mk", ".tf", ".hcl", ".pl":
		return "# ", "", true
	case ".md", ".markdown", ".html", ".htm", ".xml", ".vue", ".svg":
		return "<!-- ", " -->", true
	case ".sql":
		return "-- ", "", true
	case ".lua":
		return "-- ", "", true
	}

	// Extensionless files recognized by name.
	switch base {
	case "Dockerfile", "Makefile", "Makefile.mk", ".gitignore", ".dockerignore",
		".editorconfig", ".gitattributes":
		return "# ", "", true
	}
	return "", "", false
}

// markReview inserts reviewMarker into the header of logicalPath when its
// format supports comments. condition is the vertical condition (When/AnyOf
// files rule) included in the marker. For shebang scripts, the marker is placed
// AFTER the `#!...` line so the interpreter keeps working. Returns (content,
// true) on success and (content, false) when the comment style is unknown (the
// caller then adds the marker to the MR description).
func markReview(content []byte, logicalPath, condition string) ([]byte, bool) {
	open, closeTag, ok := commentStyle(logicalPath)
	if !ok {
		return content, false
	}
	text := reviewMarker
	if condition != "" {
		text += " " + condition
	}
	text += "; проверьте условные блоки"
	line := open + text + closeTag + "\n"

	// Already marked — do not duplicate.
	if bytes.Contains(content, []byte(reviewMarker)) {
		return content, true
	}

	// Shebang: marker after the first line.
	if bytes.HasPrefix(content, []byte("#!")) {
		if nl := bytes.IndexByte(content, '\n'); nl >= 0 {
			var b bytes.Buffer
			b.Write(content[:nl+1])
			b.WriteString(line)
			b.Write(content[nl+1:])
			return b.Bytes(), true
		}
	}

	return append([]byte(line), content...), true
}

// conditionForPath returns the files-rule condition (When or AnyOf joined by
// " | ") whose Paths globs cover logicalPath, and whether it belongs to a
// conditional vertical. Rules without a condition (no-op) are ignored. Only
// Paths (vertical inclusion) count; Remove rules describe deletion and do not
// establish vertical membership.
func conditionForPath(rules []manifest.FileRule, logicalPath string) (string, bool) {
	for i := range rules {
		r := &rules[i]
		if len(r.Paths) == 0 {
			continue
		}
		cond := ruleCondition(r)
		if cond == "" {
			continue // unconditional rule — not a "vertical".
		}
		if newGlobMatcher(r.Paths).match(logicalPath) {
			return cond, true
		}
	}
	return "", false
}

// ruleCondition formats a files-rule condition as a human-readable string.
func ruleCondition(r *manifest.FileRule) string {
	if r.When != "" {
		return r.When
	}
	if len(r.AnyOf) > 0 {
		return strings.Join(r.AnyOf, " | ")
	}
	return ""
}
