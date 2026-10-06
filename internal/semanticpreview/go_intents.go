package semanticpreview

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

type parsedGo struct {
	path    string
	raw     []byte
	set     *token.FileSet
	file    *ast.File
	anchors []resultdto.SemanticAnchor
}
type splice struct {
	edit        Edit
	start, end  int
	replacement []byte
}

func parseGo(p string, raw []byte) (*parsedGo, error) {
	if !goPath(p) || !plainLF(string(raw)) {
		return nil, ErrSyntax
	}
	set := token.NewFileSet()
	file, e := parser.ParseFile(set, p, raw, parser.ParseComments|parser.AllErrors)
	if e != nil {
		return nil, ErrSyntax
	}
	g := &parsedGo{path: p, raw: append([]byte(nil), raw...), set: set, file: file, anchors: []resultdto.SemanticAnchor{}}
	anchor := func(kind, key string, start, end int, node string) {
		g.anchors = append(g.anchors, resultdto.SemanticAnchor{Kind: kind, Key: key, StartByte: start, EndByte: end, Digest: evidencecas.Digest(raw[start:end]), NodeID: node})
	}
	boundary := g.offset(file.Name.End())
	for _, d := range file.Decls {
		if decl, ok := d.(*ast.GenDecl); ok && decl.Tok == token.IMPORT {
			boundary = g.offset(decl.End())
			for _, spec := range decl.Specs {
				imp := spec.(*ast.ImportSpec)
				value, e := strconv.Unquote(imp.Path.Value)
				if e != nil {
					return nil, ErrSyntax
				}
				alias := ""
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				start, end := g.importRange(decl, imp)
				if start >= 0 {
					anchor("import", value+"\x00"+alias, start, end, fmt.Sprintf("import:go:%s:%s:%d", p, strings.Trim(imp.Path.Value, "\""), set.Position(imp.Pos()).Line))
				}
			}
		}
		if decl, ok := d.(*ast.FuncDecl); ok && decl.Body != nil {
			anchor("function-body", decl.Name.Name, g.offset(decl.Body.Pos()), g.offset(decl.Body.End()), fmt.Sprintf("declaration:go:%s:%s:%d", p, decl.Name.Name, set.Position(decl.Pos()).Line))
		}
	}
	// A boundary is eligible only at an unambiguous LF end. This refuses
	// attached/trailing comments instead of moving their ownership implicitly.
	if end, ok := g.lineEnd(boundary); ok {
		anchor("import-boundary", "imports", boundary, end, "")
	}
	comments := map[string]int{}
	for _, group := range file.Comments {
		for _, c := range group.List {
			comments[c.Text]++
		}
	}
	for _, group := range file.Comments {
		for _, c := range group.List {
			if comments[c.Text] != 1 || !strings.HasPrefix(c.Text, "//") {
				continue
			}
			start := g.lineStart(g.offset(c.Pos()))
			end := g.offset(c.End())
			if !onlyIndent(raw[start:g.offset(c.Pos())]) {
				continue
			}
			if _, ok := g.lineEnd(end); !ok {
				continue
			}
			eligible := false
			ast.Inspect(file, func(n ast.Node) bool {
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				if c.Pos() <= block.Lbrace || c.End() >= block.Rbrace {
					return true
				}
				for _, statement := range block.List {
					if statement.Pos() < c.End() && statement.End() > c.Pos() {
						return true
					}
				}
				eligible = true
				return true
			})
			if eligible {
				anchor("comment", c.Text, start, end, "")
			}
		}
	}
	sort.Slice(g.anchors, func(i, j int) bool {
		a, b := g.anchors[i], g.anchors[j]
		if a.StartByte != b.StartByte {
			return a.StartByte < b.StartByte
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Key < b.Key
	})
	return g, nil
}
func (g *parsedGo) offset(p token.Pos) int   { return g.set.Position(p).Offset }
func (g *parsedGo) lineStart(offset int) int { return bytes.LastIndexByte(g.raw[:offset], '\n') + 1 }
func onlyIndent(b []byte) bool               { return len(bytes.Trim(b, " \t")) == 0 }
func (g *parsedGo) lineEnd(end int) (int, bool) {
	rest := g.raw[end:]
	idx := bytes.IndexByte(rest, '\n')
	if idx < 0 {
		if onlyIndent(rest) {
			return len(g.raw), true
		}
		return 0, false
	}
	if !onlyIndent(rest[:idx]) {
		return 0, false
	}
	return end + idx + 1, true
}
func (g *parsedGo) importRange(decl *ast.GenDecl, imp *ast.ImportSpec) (int, int) {
	if decl.Doc != nil || imp.Doc != nil || imp.Comment != nil {
		return -1, -1
	}
	start, end := g.offset(imp.Pos()), g.offset(imp.End())
	if len(decl.Specs) == 1 {
		start = g.offset(decl.Pos())
		end = g.offset(decl.End())
		for _, c := range g.file.Comments {
			if c.Pos() > decl.Pos() && c.End() < decl.End() {
				return -1, -1
			}
		}
	} else {
		start = g.lineStart(start)
		if !onlyIndent(g.raw[start:g.offset(imp.Pos())]) {
			return -1, -1
		}
	}
	if !onlyIndent(g.raw[g.lineStart(start):start]) {
		return -1, -1
	}
	last, ok := g.lineEnd(end)
	if !ok {
		return -1, -1
	}
	return start, last
}
func (g *parsedGo) resolve(e Edit) (splice, error) {
	if evidencecas.Digest(g.raw) != e.ExpectedFileDigest {
		return splice{}, ErrAnchor
	}
	found := false
	for _, a := range g.anchors {
		if reflect.DeepEqual(a, e.Anchor) {
			found = true
			break
		}
	}
	if !found {
		return splice{}, ErrAnchor
	}
	s := splice{edit: e, start: e.Anchor.StartByte, end: e.Anchor.EndByte}
	switch e.Intent {
	case "go.function-body.replace":
		const prefix = "package preview\nfunc target() "
		raw := []byte(prefix + e.Payload + "\n")
		set := token.NewFileSet()
		f, err := parser.ParseFile(set, "payload.go", raw, parser.ParseComments|parser.AllErrors)
		if err != nil || len(f.Decls) != 1 {
			return s, ErrSyntax
		}
		fn, ok := f.Decls[0].(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return s, ErrSyntax
		}
		// The actual body must cover every payload byte. Outer whitespace,
		// trailing comments/directives and tokens outside the body are refused.
		if set.PositionFor(fn.Body.Pos(), false).Offset != len(prefix) || set.PositionFor(fn.Body.End(), false).Offset != len(prefix)+len(e.Payload) {
			return s, ErrSyntax
		}
		s.replacement = []byte(e.Payload)
	case "go.import.add":
		s.start = e.Anchor.EndByte
		s.end = s.start
		for _, imp := range g.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == e.ImportPath {
				return s, ErrRequest
			}
			if e.Alias != "" && e.Alias != "_" && e.Alias != "." && imp.Name != nil && imp.Name.Name == e.Alias {
				return s, ErrRequest
			}
		}
		alias := ""
		if e.Alias != "" {
			alias = e.Alias + " "
		}
		s.replacement = []byte("import " + alias + strconv.Quote(e.ImportPath) + "\n")
		if s.start == len(g.raw) && (len(g.raw) == 0 || g.raw[len(g.raw)-1] != '\n') {
			s.replacement = append([]byte{'\n'}, s.replacement...)
		}
	case "go.import.remove":
		if e.Anchor.Key != e.ImportPath+"\x00"+e.Alias {
			return s, ErrAnchor
		}
		s.replacement = []byte{}
	case "go.comment-anchor.insert-statements":
		s.end = s.start
		var comment *ast.Comment
		for _, group := range g.file.Comments {
			for _, c := range group.List {
				if c.Text == e.Comment {
					comment = c
				}
			}
		}
		if comment == nil {
			return s, ErrAnchor
		}
		raw := []byte("package preview\nfunc target(){\n" + e.Payload + "\n}\n")
		f, err := parser.ParseFile(token.NewFileSet(), "payload.go", raw, parser.ParseComments|parser.AllErrors)
		if err != nil || len(f.Decls) != 1 {
			return s, ErrSyntax
		}
		fn, ok := f.Decls[0].(*ast.FuncDecl)
		if !ok || len(fn.Body.List) == 0 {
			return s, ErrSyntax
		}
		indent := string(g.raw[s.start:g.offset(comment.Pos())])
		// Indent only the first line; interior bytes may belong to raw literals
		// or comments. Preserve all authored lines and terminate the insertion
		// before the original marker without formatting unrelated tokens.
		s.replacement = []byte(indent + e.Payload)
		if !strings.HasSuffix(e.Payload, "\n") {
			s.replacement = append(s.replacement, '\n')
		}
	default:
		return s, ErrRequest
	}
	return s, nil
}
func applySplices(g *parsedGo, splices []splice) ([]byte, []resultdto.SemanticEditMapping, error) {
	sorted := append([]splice{}, splices...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].start < sorted[j].start })
	for i, s := range sorted {
		if i > 0 {
			previous := sorted[i-1]
			if previous.end > s.start || previous.start == s.start {
				return nil, nil, ErrOverlap
			}
		}
	}
	mappings := make([]resultdto.SemanticEditMapping, len(sorted))
	shift := 0
	for i, s := range sorted {
		mappings[i] = resultdto.SemanticEditMapping{ID: s.edit.ID, Path: s.edit.Path, Intent: s.edit.Intent, Before: s.edit.Anchor, AfterStartByte: s.start + shift, AfterEndByte: s.start + shift + len(s.replacement)}
		shift += len(s.replacement) - (s.end - s.start)
	}
	after := append([]byte(nil), g.raw...)
	for i := len(sorted) - 1; i >= 0; i-- {
		s := sorted[i]
		next := make([]byte, 0, len(after)-(s.end-s.start)+len(s.replacement))
		next = append(next, after[:s.start]...)
		next = append(next, s.replacement...)
		next = append(next, after[s.end:]...)
		after = next
	}
	if _, e := parseGo(g.path, after); e != nil {
		return nil, nil, e
	}
	return after, mappings, nil
}
