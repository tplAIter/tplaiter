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

// archViolation — одно нарушение arch-lint правила (проверку, docs/research/
// clean-codegen.md §1 заимствование 4 / §4 ): правило × файл рендера
// (slash-путь, относительно корня рендера комбо) × строка.
type archViolation struct {
	RuleID string
	File   string
	Line   int
	Msg    string
}

func (v archViolation) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", v.File, v.Line, v.RuleID, v.Msg)
}

// checkArchLint прогоняет манифестные lint.rules (opt-in секция манифеста,
// см. manifest.LintConfig) по рендеру одной комбо: outDir — каталог результата
// [engine.Render], files — список относительных slash-путей рендера
// ([engine.Result.Files]). Пустая секция lint (правил нет) ничего не делает —
// нулевое влияние на шаблоны/фикстуры без секции lint.
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

// runLintRule применяет одно правило к уже отфильтрованному (paths/exclude)
// списку относительных путей matched. Неизвестные ID сюда не доходят —
// manifest.Template.Validate (checkLint) отклоняет их раньше; defensive-ветка
// молчит, чтобы будущие ID не паниковали lint-template.
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

// checkASTRule парсит через go/parser каждый .go-файл из matched (нестрогие
// совпадения — не .go — пропускаются молча: правило может матчить и не-Go
// пути, если шаблон так составил paths) и прогоняет по AST соответствующую
// проверку.
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

// generatedMarkerCheckLines — сколько физических строк с начала файла
// проверяются на присутствие маркера сгенерированного кода.
const generatedMarkerCheckLines = 5

// checkGeneratedMarkerRule — правило generated-marker (проверку): файлы, попавшие
// под paths/exclude правила, обязаны нести маркер "Code generated" или
// "DO NOT EDIT" в первых [generatedMarkerCheckLines] строках. Применимо не
// только к .go-файлам (сгенерированные клиенты бывают и не-Go).
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

// newConstructorPrefix — префикс имён функций/методов-конструкторов,
// исключённых из правила ctx-first (см. checkCtxFirst).
const newConstructorPrefix = "New"

// checkCtxFirst — правило ctx-first (проверку). Точная семантика (согласована в
// описание поведения, спорные места задокументированы там же):
//
//   - проверяются ТОЛЬКО экспортируемые функции/методы (ast.IsExported по
//     имени функции; ресивер может быть любой видимости);
//   - функции/методы БЕЗ параметров пропускаются — нечего проверять;
//   - функции/методы с именем, начинающимся на "New" (конструкторы),
//     исключены целиком независимо от сигнатуры;
//   - иначе первый параметр обязан быть типа context.Context (обычный или
//     вариадик `...context.Context`); любой другой тип первого параметра
//     (включая обычный вариадик над другим типом, напр. `...Option`) —
//     нарушение.
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

// describeFunc возвращает человекочитаемое описание объявления для сообщения
// о нарушении: "функция Foo" либо "метод (*T).Foo"/"метод T.Foo".
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

// isContextContextType сообщает, является ли тип параметра context.Context —
// проверяется имя пакета-селектора строго "context" (алиасы импорта в
// generated-коде не встречаются, поэтому без резолва импортов); вариадик
// разворачивается до типа элемента.
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

// checkNoInit — правило no-init (проверку): запрет func init() (без ресивера) в
// путях правила.
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

// checkNoPanic — правило no-panic (проверку): запрет вызова panic() внутри тела
// любой функции/метода, КРОМЕ func main и func init (обе без ресивера).
// Замыкания (ast.FuncLit), объявленные внутри разрешённой main/init, входят в
// её поддерево и не проверяются отдельно — panic внутри такого замыкания
// считается "внутри main/init" (задокументированное спорное решение).
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

// matchLintFiles возвращает подмножество files, матчащих хотя бы один глоб
// includes и не матчащих ни один глоб excludes.
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

// lintGlobSet — набор glob-паттернов, скомпилированных в регулярные
// выражения. Продублировано из internal/engine/glob.go (тот же язык глобов,
// : `*` в пределах сегмента, `**` как отдельный сегмент — ноль или
// более каталогов, `?` — один символ кроме `/`) АДДИТИВНО — там функции не
// экспортированы, а сам internal/engine расширять ради одного матчера не
// нужно (тот же паттерн дублирования уже применён в internal/stats/glob.go).
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

// lintGlobToRegexp — копия engine.globToRegexp/writeDoubleStarSegment/
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
