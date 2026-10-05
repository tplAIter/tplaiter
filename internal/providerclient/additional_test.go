package providerclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPublicSchemaPin(t *testing.T) {
	raw, err := os.ReadFile("../../schema/knowledge.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if digest(raw) != KnowledgeSchemaSHA256 {
		t.Fatal("C01 schema drift")
	}
}

// Portable product source assertions: the client must consume host-owned I/O.
// Exact review source hashes are checked separately by private review tooling.
func TestRuntimeUsesHostOwnedIO(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		aliases := map[string]string{}
		for _, imp := range source.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			switch path {
			case "os", "os/exec", "syscall", "net/http", "plugin", "unsafe":
				t.Errorf("runtime must not discover files, processes or network clients: %s imports %s", name, path)
			}
			alias := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			aliases[alias] = path
			if path == "net" && alias == "." {
				t.Error("dot net import defeats host I/O assertion")
			}
		}
		ast.Inspect(source, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if aliases[ident.Name] == "net" && (strings.HasPrefix(selector.Sel.Name, "Dial") || strings.HasPrefix(selector.Sel.Name, "Listen")) {
				t.Errorf("runtime must receive a host-owned connection: %s calls %s", name, selector.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no runtime source assertions performed")
	}
}
