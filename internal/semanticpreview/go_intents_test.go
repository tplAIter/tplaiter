package semanticpreview

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func previewAnchor(t *testing.T, g *parsedGo, kind, key string) resultdto.SemanticAnchor {
	t.Helper()
	for _, a := range g.anchors {
		if a.Kind == kind && a.Key == key {
			return a
		}
	}
	t.Fatal("missing native syntax anchor", kind, key)
	return resultdto.SemanticAnchor{}
}
func previewEdit(g *parsedGo, intent string, a resultdto.SemanticAnchor) Edit {
	return Edit{ID: "edit1", Path: g.path, Intent: intent, ExpectedFileDigest: evidencecas.Digest(g.raw), BeforeGraphDigest: evidencecas.Digest(nil), Anchor: a}
}
func TestGoPreviewActualTokenSplices(t *testing.T) {
	original := []byte("package service\nimport \"fmt\"\nfunc Handle(){\n\t// existing-step\n\tfmt.Println(1)\n}\n")
	cases := []struct{ name, intent, kind, key, payload, importPath, comment, want string }{
		{"body", "go.function-body.replace", "function-body", "Handle", "{ fmt.Println(2) }", "", "", "func Handle(){ fmt.Println(2) }"},
		{"add-import", "go.import.add", "import-boundary", "imports", "", "context", "", "import \"context\"\n"},
		{"remove-import", "go.import.remove", "import", "fmt\x00", "", "fmt", "", "package service\nfunc Handle()"},
		{"comment", "go.comment-anchor.insert-statements", "comment", "// existing-step", "fmt.Println(2)", "", "// existing-step", "\tfmt.Println(2)\n\t// existing-step"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, e := parseGo("service.go", original)
			if e != nil {
				t.Fatal(e)
			}
			edit := previewEdit(g, c.intent, previewAnchor(t, g, c.kind, c.key))
			edit.Payload = c.payload
			edit.ImportPath = c.importPath
			edit.Comment = c.comment
			if e = (Request{APIVersion: RequestVersion, Action: "preview", Edits: []Edit{edit}}).Validate(); e != nil {
				t.Fatal(e)
			}
			s, e := g.resolve(edit)
			if e != nil {
				t.Fatal(e)
			}
			after, mapping, e := applySplices(g, []splice{s})
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Contains(after, []byte(c.want)) || len(mapping) != 1 || mapping[0].ID != edit.ID {
				t.Fatal("actual AST splice/mapping differs", string(after))
			}
			if !bytes.Equal(original, g.raw) {
				t.Fatal("input mutated")
			}
			// All bytes outside the independently resolved edit interval survive.
			if !bytes.Equal(after[:s.start], original[:s.start]) || !bytes.Equal(after[s.start+len(s.replacement):], original[s.end:]) {
				t.Fatal("unrelated syntax bytes changed")
			}
		})
	}
}
func TestGoPreviewRefusesStaleAmbiguousAndOverlapping(t *testing.T) {
	raw := []byte("package service\nfunc Handle(){\n // existing-step\n println(1)\n}\n")
	g, e := parseGo("service.go", raw)
	if e != nil {
		t.Fatal(e)
	}
	body := previewEdit(g, "go.function-body.replace", previewAnchor(t, g, "function-body", "Handle"))
	body.Payload = "{ println(2) }"
	stale := body
	stale.Anchor.StartByte++
	if _, e = g.resolve(stale); e == nil {
		t.Fatal("caller byte offset trusted")
	}
	malformed := body
	malformed.Payload = "{ invalid("
	if _, e = g.resolve(malformed); e == nil {
		t.Fatal("malformed payload accepted")
	}
	comment := previewEdit(g, "go.comment-anchor.insert-statements", previewAnchor(t, g, "comment", "// existing-step"))
	comment.Comment = "// existing-step"
	comment.Payload = "println(3)"
	a, _ := g.resolve(body)
	b, _ := g.resolve(comment)
	if _, _, e = applySplices(g, []splice{a, b}); e != ErrOverlap {
		t.Fatal("body/comment overlapping edits admitted", e)
	}
	ambiguous := bytes.Replace(raw, []byte(" // existing-step\n"), []byte(" // existing-step\n // existing-step\n"), 1)
	other, e := parseGo("service.go", ambiguous)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range other.anchors {
		if a.Kind == "comment" {
			t.Fatal("ambiguous comment anchor exposed")
		}
	}
	if _, e = parseGo("service.go", bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))); e == nil {
		t.Fatal("CRLF silently normalized")
	}
}

func TestGoPreviewCompleteDiffAndWorkRefusal(t *testing.T) {
	before := []byte("package service\nfunc Handle(){println(1)}")
	after := []byte("package service\nfunc Handle(){println(2)}")
	diff, e := unifiedDiff("service.go", before, after)
	if e != nil || !strings.Contains(diff, "-func Handle(){println(1)}") || !strings.Contains(diff, "+func Handle(){println(2)}") || strings.Count(diff, "\\ No newline at end of file") != 2 {
		t.Fatal("incomplete actual diff", diff, e)
	}
	if _, e = unifiedDiff("service.go", []byte(strings.Repeat("old\n", 1500)), []byte(strings.Repeat("new\n", 1500))); e != ErrBudget {
		t.Fatal("unbounded diff work accepted", e)
	}
}

func TestGoPreviewFunctionBodyExactParsedSpan(t *testing.T) {
	original := []byte("package service\ntype Service struct{}\nfunc (s *Service) Handle(v int) int { return v }\n")
	g, err := parseGo("service.go", original)
	if err != nil {
		t.Fatal(err)
	}
	edit := previewEdit(g, "go.function-body.replace", previewAnchor(t, g, "function-body", "Handle"))
	for _, payload := range []string{
		"{ return v }\n// outside body }",
		"{ return v } /* outside body */ // }",
		"{ return v }\n//line outside.go:1\n// }",
		" { return v }",
		"{ return v } ",
		"{ return v }\n",
	} {
		t.Run(payload, func(t *testing.T) {
			// These are valid Go wrapper files, including the outside-body
			// comments. The body-only intent must impose the narrower scope.
			if _, err := parser.ParseFile(token.NewFileSet(), "payload.go", "package service\nfunc target() "+payload+"\n", parser.ParseComments|parser.AllErrors); err != nil {
				t.Fatal("negative fixture is not syntactically valid", err)
			}
			bad := edit
			bad.Payload = payload
			if _, err := g.resolve(bad); err != ErrSyntax {
				t.Fatal("admitted bytes outside the native body span", err)
			}
		})
	}
	edit.Payload = "{\n // comment inside the body }\n _ = `first\nsecond`\n return v + 1\n}"
	s, err := g.resolve(edit)
	if err != nil {
		t.Fatal("valid multiline body refused", err)
	}
	after, mappings, err := applySplices(g, []splice{s})
	if err != nil {
		t.Fatal(err)
	}
	next, err := parseGo(g.path, after)
	if err != nil {
		t.Fatal(err)
	}
	fn := next.file.Decls[1].(*ast.FuncDecl)
	if !bytes.Equal(after[next.offset(fn.Body.Pos()):next.offset(fn.Body.End())], []byte(edit.Payload)) || len(fn.Recv.List) != 1 || len(fn.Type.Params.List) != 1 || len(fn.Type.Results.List) != 1 {
		t.Fatal("lost exact parsed body, receiver or signature")
	}
	if len(mappings) != 1 || !bytes.Equal(after[:s.start], original[:s.start]) || !bytes.Equal(after[s.start+len(s.replacement):], original[s.end:]) || !bytes.Equal(g.raw, original) {
		t.Fatal("body replacement changed unrelated original bytes")
	}
}

func TestGoPreviewCommentStatementsPreserveMultilineTokenBytes(t *testing.T) {
	original := []byte("package service\nfunc Handle(){\n\t// existing-step\n\tprintln(0)\n}\n")
	g, err := parseGo("service.go", original)
	if err != nil {
		t.Fatal(err)
	}
	literalValues := func(f *ast.File) []string {
		t.Helper()
		values := []string{}
		ast.Inspect(f, func(n ast.Node) bool {
			literal, ok := n.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, value)
			}
			return true
		})
		return values
	}
	for _, payload := range []string{
		"println(`first\nsecond`)",
		"println(`first\n\tsecond\n\nthird`)\nprintln(\"last\")\n",
		"if true {\n println(`inside\nraw`)\n}\nprintln(\"outside\")",
		"println(1)\n/* authored\ncomment */\nprintln(2)\n\n",
	} {
		t.Run(payload, func(t *testing.T) {
			wrapped, err := parser.ParseFile(token.NewFileSet(), "payload.go", "package service\nfunc target(){\n"+payload+"\n}\n", parser.ParseComments|parser.AllErrors)
			if err != nil {
				t.Fatal(err)
			}
			edit := previewEdit(g, "go.comment-anchor.insert-statements", previewAnchor(t, g, "comment", "// existing-step"))
			edit.Comment = "// existing-step"
			edit.Payload = payload
			s, err := g.resolve(edit)
			if err != nil {
				t.Fatal("functional multiline insertion refused", err)
			}
			after, mappings, err := applySplices(g, []splice{s})
			if err != nil {
				t.Fatal(err)
			}
			next, err := parseGo(g.path, after)
			if err != nil {
				t.Fatal(err)
			}
			wantValues, gotValues := literalValues(wrapped), literalValues(next.file)
			if strings.Join(wantValues, "\x00") != strings.Join(gotValues, "\x00") || len(wantValues) != len(gotValues) {
				t.Fatalf("AST raw literal values changed: %q -> %q", wantValues, gotValues)
			}
			if !bytes.Equal(s.replacement[1:1+len(payload)], []byte(payload)) || len(mappings) != 1 || !bytes.Equal(after[:s.start], original[:s.start]) || !bytes.Equal(after[s.start+len(s.replacement):], original[s.end:]) || !bytes.Equal(g.raw, original) {
				t.Fatal("insertion changed payload interior or unrelated original bytes")
			}
		})
	}
}
