// Package semanticgraph extracts conservative syntax facts with explicit provenance.
// It intentionally does not claim resolved calls or compiler semantics.
package semanticgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

type Options struct {
	Verify   bool
	MaxFiles int
}

func Analyze(ctx context.Context, root string, opts Options) (graphdoc.Document, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return graphdoc.Document{}, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return graphdoc.Document{}, err
	}
	if !info.IsDir() {
		return graphdoc.Document{}, fmt.Errorf("semanticgraph: root is not a directory")
	}
	d := graphdoc.New()
	d.Producer = "tplaiter semanticgraph"
	files := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if path != root {
			if entry.IsDir() {
				if entry.Type()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, ".tplaiter/") || strings.HasPrefix(rel, ".tplater/") {
			return nil
		}
		lang := language(rel)
		if lang == "" {
			return nil
		}
		files++
		if opts.MaxFiles > 0 && files > opts.MaxFiles {
			return fmt.Errorf("semanticgraph: file limit exceeded")
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		addFile(&d, lang, rel, src)
		return nil
	})
	if err != nil {
		return d, err
	}
	if len(d.Nodes) == 0 {
		return d, fmt.Errorf("semanticgraph: no supported source files")
	}
	if err := d.Canonicalize(); err != nil {
		return d, err
	}
	return d, nil
}

func addFile(d *graphdoc.Document, lang, rel string, src []byte) {
	file := "file:" + lang + ":" + rel
	d.Nodes = append(d.Nodes, graphdoc.Node{ID: file, Kind: "file", Language: lang, Path: rel, Provenance: []graphdoc.Provenance{{Source: "filesystem", Evidence: digest(src), Detected: true}}})
	if lang == "go" {
		parseGo(d, file, rel, src)
	} else {
		parseRust(d, file, rel, src)
	}
}

func parseGo(d *graphdoc.Document, file, rel string, src []byte) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, rel, src, parser.ParseComments)
	if err != nil {
		d.Diagnostics = append(d.Diagnostics, graphdoc.Diagnostic{Code: "parse-error", Severity: "warning", Message: "Go syntax could not be parsed; file node retained", Path: rel})
		return
	}
	line := func(p token.Pos) int { return fs.Position(p).Line }
	pkg := "package:go:" + rel + ":" + f.Name.Name
	d.Nodes = append(d.Nodes, graphdoc.Node{ID: pkg, Kind: "package", Language: "go", Path: rel, Name: f.Name.Name})
	d.Edges = append(d.Edges, graphdoc.Edge{From: file, To: pkg, Kind: "contains-package", Provenance: []graphdoc.Provenance{{Source: "go/parser", Evidence: "syntax", Detected: true}}})
	for _, imp := range f.Imports {
		name := strings.Trim(imp.Path.Value, "\"")
		ln := line(imp.Pos())
		id := fmt.Sprintf("import:go:%s:%s:%d", rel, name, ln)
		d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "import", Language: "go", Path: rel, Name: name, Line: ln})
		d.Edges = append(d.Edges, graphdoc.Edge{From: file, To: id, Kind: "imports", Provenance: []graphdoc.Provenance{{Source: "go/parser", Evidence: "syntax", Detected: true}}})
	}
	for _, decl := range f.Decls {
		n, ok := decl.(*ast.FuncDecl)
		if !ok || n.Name == nil {
			continue
		}
		ln := line(n.Pos())
		id := fmt.Sprintf("declaration:go:%s:%s:%d", rel, n.Name.Name, ln)
		d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "declaration", Language: "go", Path: rel, Name: n.Name.Name, Line: ln})
		d.Edges = append(d.Edges, graphdoc.Edge{From: file, To: id, Kind: "declares", Provenance: []graphdoc.Provenance{{Source: "go/parser", Evidence: "syntax", Detected: true}}})
	}
}

func parseRust(d *graphdoc.Document, file, rel string, src []byte) {
	for i, line := range strings.Split(string(src), "\n") {
		n := i + 1
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "use ") || strings.HasPrefix(t, "extern crate ") {
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "use "), "extern crate "))
			name = strings.TrimSuffix(name, ";")
			id := fmt.Sprintf("import:rust:%s:%s:%d", rel, name, n)
			d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "import", Language: "rust", Path: rel, Name: name, Line: n})
			d.Edges = append(d.Edges, graphdoc.Edge{From: file, To: id, Kind: "imports", Provenance: []graphdoc.Provenance{{Source: "rust lexer", Evidence: "syntax", Detected: true}}})
		}
		if strings.Contains(t, "fn ") {
			fields := strings.Fields(t)
			for j, field := range fields {
				if field != "fn" || j+1 >= len(fields) {
					continue
				}
				name := strings.Split(fields[j+1], "(")[0]
				if name == "" {
					break
				}
				id := fmt.Sprintf("declaration:rust:%s:%s:%d", rel, name, n)
				d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "declaration", Language: "rust", Path: rel, Name: name, Line: n})
				d.Edges = append(d.Edges, graphdoc.Edge{From: file, To: id, Kind: "declares", Provenance: []graphdoc.Provenance{{Source: "rust lexer", Evidence: "syntax", Detected: true}}})
				break
			}
		}
	}
}

func language(p string) string {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".go":
		return "go"
	case ".rs":
		return "rust"
	}
	return ""
}
func digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
