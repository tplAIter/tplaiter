package blockmarkers

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
)

func goComments(path string, source []byte) ([]commentSpan, error) {
	// A BOM is not a managed-marker transport feature. Rejecting it keeps all
	// reported byte offsets literal and prevents a parser-normalized prefix.
	if bytes.HasPrefix(source, []byte{0xef, 0xbb, 0xbf}) {
		return nil, &Error{Path: path, Code: CodeInvalidSource}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.ParseComments)
	if err != nil || file == nil {
		return nil, &Error{Path: path, Code: CodeSyntax}
	}
	tokFile := fset.File(file.Pos())
	if tokFile == nil {
		return nil, &Error{Path: path, Code: CodeSyntax}
	}
	comments := make([]commentSpan, 0)
	for _, group := range file.Comments {
		for _, comment := range group.List {
			start := tokFile.Offset(comment.Pos())
			end, ok := originalGoCommentEnd(source, start)
			if !ok {
				return nil, &Error{Path: path, Code: CodeSyntax}
			}
			comments = append(comments, commentSpan{start: start, end: end})
		}
	}
	return comments, nil
}

func originalGoCommentEnd(source []byte, start int) (int, bool) {
	if start < 0 || start+2 > len(source) || source[start] != '/' {
		return 0, false
	}
	switch source[start+1] {
	case '/':
		end := start + 2
		for end < len(source) && source[end] != '\n' && source[end] != '\r' {
			end++
		}
		return end, true
	case '*':
		if rel := bytes.Index(source[start+2:], []byte("*/")); rel >= 0 {
			return start + 2 + rel + 2, true
		}
	}
	return 0, false
}

// Keep ast imported as a compile-time guard for parser.ParseFile's AST based
// comment path; it also documents that this scanner is not a custom Go lexer.
var _ *ast.File
