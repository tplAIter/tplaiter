package inittemplate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// archViolation — one arch-lint violation: rule × rendered file (slash path
// relative to the combo render root) × line.
type archViolation struct {
	RuleID string
	File   string
	Line   int
	Msg    string
}

func (v archViolation) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", v.File, v.Line, v.RuleID, v.Msg)
}

// checkArchLint applies manifest lint.rules (opt-in; see manifest.LintConfig) to
// one combo render: outDir is the [engine.Render] result directory and files are
// relative slash paths ([engine.Result.Files]). An empty lint section does
// nothing, preserving templates/fixtures without lint.
func checkArchLint(tpl *manifest.Template, outDir string, files []string) error {
	rules := tpl.Lint.Rules
	if len(rules) == 0 {
		return nil
	}

	var violations []archViolation
	for i := range rules {
		r := &rules[i]
		matched := matchLintFiles(files, r.Paths, r.Exclude)
		vs, err := runLintRule(r.ID, outDir, matched)
		if err != nil {
			return err
		}
		violations = append(violations, vs...)
	}
	if len(violations) == 0 {
		return nil
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		if violations[i].Line != violations[j].Line {
			return violations[i].Line < violations[j].Line
		}
		return violations[i].RuleID < violations[j].RuleID
	})
	parts := make([]string, len(violations))
	for i, v := range violations {
		parts[i] = v.String()
	}
	return fmt.Errorf("arch-lint: %d нарушени(е/й):\n    - %s", len(violations), strings.Join(parts, "\n    - "))
}

// runLintRule applies one rule to the already filtered (paths/exclude) list of
// relative paths matched. Unknown IDs do not reach it: manifest.Template.Validate
// (checkLint) rejects them earlier; the defensive branch stays quiet for future IDs.
func runLintRule(ruleID, outDir string, matched []string) ([]archViolation, error) {
	switch ruleID {
	case manifest.LintRuleGeneratedMarker:
		return checkGeneratedMarkerRule(outDir, matched)
	case manifest.LintRuleCtxFirst, manifest.LintRuleNoInit, manifest.LintRuleNoPanic:
		return checkASTRule(ruleID, outDir, matched)
	default:
		return nil, nil
	}
}

// checkASTRule parses each .go file in matched with go/parser (non-Go matches
// are silently skipped; paths may intentionally match non-Go files) and runs
// the corresponding AST check.
func checkASTRule(ruleID, outDir string, matched []string) ([]archViolation, error) {
	var out []archViolation
	for _, rel := range matched {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		fset := token.NewFileSet()
		abs := filepath.Join(outDir, filepath.FromSlash(rel))
		astFile, err := parser.ParseFile(fset, abs, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("arch-lint %s: go/parser: %s: %w", ruleID, rel, err)
		}
		switch ruleID {
		case manifest.LintRuleCtxFirst:
			out = append(out, checkCtxFirst(fset, astFile, rel)...)
		case manifest.LintRuleNoInit:
			out = append(out, checkNoInit(fset, astFile, rel)...)
		case manifest.LintRuleNoPanic:
			out = append(out, checkNoPanic(fset, astFile, rel)...)
		}
	}
	return out, nil
}

// generatedMarkerCheckLines — number of physical lines from the file start
// checked for a generated-code marker.
const generatedMarkerCheckLines = 5

// checkGeneratedMarkerRule checks generated-marker: files matching paths/exclude
// must carry "Code generated" or "DO NOT EDIT" within the first
// [generatedMarkerCheckLines] lines. It applies beyond .go files.
func checkGeneratedMarkerRule(outDir string, matched []string) ([]archViolation, error) {
	var out []archViolation
	for _, rel := range matched {
		abs := filepath.Join(outDir, filepath.FromSlash(rel))
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, fmt.Errorf("arch-lint %s: чтение %s: %w", manifest.LintRuleGeneratedMarker, rel, err)
		}
		if !hasGeneratedMarker(data) {
			out = append(out, archViolation{
				RuleID: manifest.LintRuleGeneratedMarker,
				File:   rel,
				Line:   1,
				Msg:    fmt.Sprintf(`в первых %d строках отсутствует маркер "Code generated"/"DO NOT EDIT"`, generatedMarkerCheckLines),
			})
		}
	}
	return out, nil
}

func hasGeneratedMarker(data []byte) bool {
	lines := strings.SplitN(string(data), "\n", generatedMarkerCheckLines+1)
	if len(lines) > generatedMarkerCheckLines {
		lines = lines[:generatedMarkerCheckLines]
	}
	head := strings.Join(lines, "\n")
	return strings.Contains(head, "Code generated") || strings.Contains(head, "DO NOT EDIT")
}

// newConstructorPrefix — prefix of constructor function/method names excluded
// from ctx-first (see checkCtxFirst).
const newConstructorPrefix = "New"

// checkCtxFirst checks the ctx-first rule. Exact semantics:
//
//   - ONLY exported functions/methods are checked (ast.IsExported by function name;
//     receiver visibility is irrelevant);
//   - functions/methods without parameters are skipped;
//   - names beginning with "New" (constructors) are always excluded;
//   - otherwise the first parameter must be context.Context (ordinary or
//     variadic `...context.Context`); any other type is a violation.
func checkCtxFirst(fset *token.FileSet, f *ast.File, rel string) []archViolation {
	out := make([]archViolation, 0, len(f.Decls))
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if !ast.IsExported(fd.Name.Name) {
			continue
		}
		if strings.HasPrefix(fd.Name.Name, newConstructorPrefix) {
			continue
		}
		if fd.Type.Params == nil || len(fd.Type.Params.List) == 0 {
			continue
		}
		first := fd.Type.Params.List[0]
		if isContextContextType(first.Type) {
			continue
		}
		out = append(out, archViolation{
			RuleID: manifest.LintRuleCtxFirst,
			File:   rel,
			Line:   fset.Position(first.Pos()).Line,
			Msg:    describeFunc(fd) + ": первый параметр не context.Context",
		})
	}
	return out
}

// describeFunc returns a human-readable declaration description for violations:
// "function Foo" or "method (*T).Foo"/"method T.Foo".
func describeFunc(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return fmt.Sprintf("метод %s.%s", recvTypeName(fd.Recv.List[0].Type), fd.Name.Name)
	}
	return "функция " + fd.Name.Name
}

func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "*" + recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return "?"
	}
}

// isContextContextType reports whether a parameter type is context.Context.
// It requires selector package name "context" (generated code has no import
// aliases, so imports are not resolved); variadic types are reduced to elements.
func isContextContextType(expr ast.Expr) bool {
	if e, ok := expr.(*ast.Ellipsis); ok {
		expr = e.Elt
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "context" && sel.Sel.Name == "Context"
}

// checkNoInit enforces no-init: disallow func init() (without a receiver) in rule paths.
func checkNoInit(fset *token.FileSet, f *ast.File, rel string) []archViolation {
	out := make([]archViolation, 0, len(f.Decls))
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		if fd.Name.Name != "init" {
			continue
		}
		out = append(out, archViolation{
			RuleID: manifest.LintRuleNoInit,
			File:   rel,
			Line:   fset.Position(fd.Pos()).Line,
			Msg:    "func init() запрещён в этом пути",
		})
	}
	return out
}

// checkNoPanic enforces no-panic: disallow panic() in any function/method body
// except func main and func init (both without receivers). Function literals
// inside allowed main/init belong to its subtree and are not checked separately;
// panic there counts as inside main/init (documented tradeoff).
func checkNoPanic(fset *token.FileSet, f *ast.File, rel string) []archViolation {
	var out []archViolation
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if fd.Recv == nil && (fd.Name.Name == "main" || fd.Name.Name == "init") {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "panic" {
				return true
			}
			out = append(out, archViolation{
				RuleID: manifest.LintRuleNoPanic,
				File:   rel,
				Line:   fset.Position(call.Pos()).Line,
				Msg:    "panic() запрещён вне func main/func init",
			})
			return true
		})
	}
	return out
}

// matchLintFiles returns files matching at least one includes glob and no excludes glob.
func matchLintFiles(files, includes, excludes []string) []string {
	inc := newLintGlobSet(includes)
	exc := newLintGlobSet(excludes)
	out := make([]string, 0, len(files))
	for _, f := range files {
		if !inc.matchAny(f) {
			continue
		}
		if exc.matchAny(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// lintGlobSet — glob patterns compiled into regular expressions. Duplicated
// additively from internal/engine/glob.go (same language: `*` within a segment,
// `**` as a segment for zero or more directories, `?` except `/`) because those
// functions are unexported and expanding engine for one matcher is unnecessary.
type lintGlobSet struct {
	res []*regexp.Regexp
}

func newLintGlobSet(globs []string) *lintGlobSet {
	gs := &lintGlobSet{res: make([]*regexp.Regexp, 0, len(globs))}
	for _, g := range globs {
		gs.res = append(gs.res, lintGlobToRegexp(g))
	}
	return gs
}

func (g *lintGlobSet) matchAny(path string) bool {
	for _, re := range g.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// lintGlobToRegexp — copy of engine.globToRegexp/writeDoubleStarSegment/
// segmentToRegexp.
func lintGlobToRegexp(glob string) *regexp.Regexp {
	segs := strings.Split(glob, "/")
	var b strings.Builder
	b.WriteString("^")
	needSlash := false
	for i, seg := range segs {
		if seg == "**" && len(segs) > 1 {
			writeLintDoubleStarSegment(&b, i, len(segs), needSlash)
			needSlash = false
			continue
		}
		if needSlash {
			b.WriteString("/")
		}
		b.WriteString(lintSegmentToRegexp(seg))
		needSlash = true
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func writeLintDoubleStarSegment(b *strings.Builder, i, total int, needSlash bool) {
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

func lintSegmentToRegexp(seg string) string {
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
