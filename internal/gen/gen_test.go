package gen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// TestNewContextDerivations checks derived names (Pascal/Camel/Snake/Kebab).
func TestNewContextDerivations(t *testing.T) {
	cases := []struct {
		raw, pascal, camel, snake, kebab string
	}{
		{"CreateOrder", "CreateOrder", "createOrder", "create_order", "create-order"},
		{"create_order", "CreateOrder", "createOrder", "create_order", "create-order"},
		{"HTTPClient", "HttpClient", "httpClient", "http_client", "http-client"},
	}
	for _, c := range cases {
		ctx, err := newContext(c.raw, settings.Values{}, manifest.ProjectInfo{})
		if err != nil {
			t.Fatalf("newContext(%q): %v", c.raw, err)
		}
		if ctx.Name.Pascal != c.pascal || ctx.Name.Camel != c.camel || ctx.Name.Snake != c.snake || ctx.Name.Kebab != c.kebab {
			t.Errorf("newContext(%q) = %+v, want {%q %q %q %q}", c.raw, ctx.Name, c.pascal, c.camel, c.snake, c.kebab)
		}
	}
}

func TestNewContextInvalidName(t *testing.T) {
	if _, err := newContext("   ", settings.Values{}, manifest.ProjectInfo{}); err == nil {
		t.Error("expected error for blank name")
	}
	if _, err := newContext("123", settings.Values{}, manifest.ProjectInfo{}); err == nil {
		t.Error("expected error for name that derives an invalid Go identifier")
	}
}

func TestLookupUnknownKind(t *testing.T) {
	tpl := &manifest.Template{Generators: []manifest.Generator{{Kind: "use-case"}, {Kind: "dao"}}}
	_, err := Lookup(tpl, "nope")
	if err == nil || !strings.Contains(err.Error(), "dao, use-case") {
		t.Fatalf("expected error listing sorted kinds, got %v", err)
	}
}

func TestEvalGate(t *testing.T) {
	values := settings.Values{"brokers": []string{"kafka"}}

	ok, err := evalGate(nil, values)
	if err != nil || !ok {
		t.Errorf("empty when must always be available: ok=%v err=%v", ok, err)
	}

	ok, err = evalGate([]string{"brokers=kafka"}, values)
	if err != nil || !ok {
		t.Errorf("expected available: ok=%v err=%v", ok, err)
	}

	// OR semantics: one TRUE condition in the list is sufficient.
	ok, err = evalGate([]string{"brokers=rabbitmq", "brokers=kafka"}, values)
	if err != nil || !ok {
		t.Errorf("expected OR semantics to make this available: ok=%v err=%v", ok, err)
	}

	ok, err = evalGate([]string{"brokers=rabbitmq"}, values)
	if err != nil || ok {
		t.Errorf("expected unavailable: ok=%v err=%v", ok, err)
	}
}

// writeFile creates a file with content, creating missing directories.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type treeEntry struct {
	mode os.FileMode
	data []byte
}

func snapshotTree(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	out := make(map[string]treeEntry)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := treeEntry{mode: info.Mode()}
		if info.Mode().IsRegular() {
			entry.data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		out[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

func assertTreeEqual(t *testing.T, want, got map[string]treeEntry) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("project tree changed:\nwant=%#v\ngot=%#v", want, got)
	}
}

func assertExecutionUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrExecutionUnavailable) {
		t.Fatalf("expected typed execution denial, got %v", err)
	}
}

const appGoStub = `package app

import (
	"log/slog"

	"example.invalid/demo/internal/usecase"
)

func New(logger *slog.Logger) error {
	_ = usecase.Placeholder
	// CODEGEN:WIRING — here tplater gen use-case adds new use cases.
	return nil
}
`

const usecaseSnippetTmpl = `// Package usecase contains business use cases for the service.
package usecase

// Placeholder exists so the package is not empty until the first gen.
var Placeholder int

// {{ .Name.Pascal }}UseCase — use case {{ .Name.Pascal }}.
type {{ .Name.Pascal }}UseCase struct{}
`

const usecaseWiringTmpl = `	{{ .Marker }}
	_ = usecase.{{ .Name.Pascal }}UseCase{}
`

// setupProject creates a minimal project: go.mod, app.go with a CODEGEN:WIRING
// anchor, the usecase package, and a .tplaiter/generators directory with use-case snippets.
func setupProject(t *testing.T) (dir string, tpl *manifest.Template) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, dir, "go.mod", "module example.invalid/demo\n\ngo 1.26\n")
	writeFile(t, dir, "internal/app/app.go", appGoStub)
	writeFile(t, dir, ".tplaiter/generators/use-case.go.tmpl", usecaseSnippetTmpl)
	writeFile(t, dir, ".tplaiter/generators/use-case.anchor.tmpl", usecaseWiringTmpl)

	tpl = &manifest.Template{
		Generators: []manifest.Generator{
			{
				Kind:        "use-case",
				Description: "Use case",
				Snippet:     "use-case.go.tmpl",
				Target:      "internal/usecase/{{ .Name.Snake }}.go",
				Anchors: []manifest.Anchor{
					{File: "internal/app/app.go", Anchor: "CODEGEN:WIRING", Insert: "use-case.anchor.tmpl"},
				},
			},
			{
				Kind:        "kafka-consumer",
				Description: "Kafka consumer",
				Snippet:     "use-case.go.tmpl",
				Target:      "internal/api/events/kafka/{{ .Name.Snake }}_consumer.go",
				When:        []string{"brokers=kafka"},
			},
		},
	}
	return dir, tpl
}

func TestGenerate_CreatesFileAndInsertsAnchorIdempotently(t *testing.T) {
	dir, tpl := setupProject(t)

	opts := Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{},
		NoBuild:       true,
	}

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func TestGenerate_UnknownKind(t *testing.T) {
	dir, tpl := setupProject(t)
	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), NoBuild: true}
	_, err := Generate(context.Background(), tpl, "nope", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("expected unknown kind error, got %v", err)
	}
}

func TestGenerate_WhenGateBlocks(t *testing.T) {
	dir, tpl := setupProject(t)
	opts := Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{"brokers": []string{}},
		NoBuild:       true,
	}
	_, err := Generate(context.Background(), tpl, "kafka-consumer", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "settings set brokers=kafka") {
		t.Errorf("expected when-gate error mentioning `settings set`, got %v", err)
	}

	// Even with valid settings, execution remains unavailable.
	opts.Values = settings.Values{"brokers": []string{"kafka"}}
	before := snapshotTree(t, dir)
	_, err = Generate(context.Background(), tpl, "kafka-consumer", "Foo", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func TestGenerate_MissingAnchorFails(t *testing.T) {
	dir, tpl := setupProject(t)
	// Corrupt app.go — its anchor is gone.
	writeFile(t, dir, "internal/app/app.go", "package app\n")

	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), NoBuild: true}
	_, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Errorf("expected anchor-not-found error, got %v", err)
	}
	// Nothing should be created when anchor preparation fails (before writing).
	if _, statErr := os.Stat(filepath.Join(dir, "internal/usecase/foo.go")); statErr == nil {
		t.Error("target file must not be created when anchor preparation fails")
	}
}

// TestGenerate_RollbackOnBuildFailure records the former executable-success
// contract; generation now denies before any filesystem effect.
func TestGenerate_RollbackOnBuildFailure(t *testing.T) {
	dir, tpl := setupProject(t)
	// Corrupt the snippet: an unclosed struct brace.
	writeFile(t, dir, ".tplaiter/generators/use-case.go.tmpl", "package usecase\n\ntype {{ .Name.Pascal }}UseCase struct {\n")

	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath)} // NoBuild: false (default)

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func setupRustProject(t *testing.T) (dir string, tpl *manifest.Template, original string) {
	t.Helper()
	dir = t.TempDir()
	original = "// CODEGEN:HTTP_ROUTES\n"
	writeFile(t, dir, "src/http/router.rs", original)
	writeFile(t, dir, ".tplaiter/generators/handler.rs.tmpl", "pub struct {{ .Name.Pascal }}Handler;\n")
	writeFile(t, dir, ".tplaiter/generators/handler.anchor.tmpl", "// {{ .Marker }}\nlet _ = {{ .Name.Pascal }}Handler;\n")
	tpl = &manifest.Template{
		Commands: map[string]manifest.Command{"build": {Run: "cargo check --workspace"}},
		Generators: []manifest.Generator{{
			Kind: "handler", Snippet: "handler.rs.tmpl", Target: "src/http/{{ .Name.Snake }}.rs",
			Anchors: []manifest.Anchor{{File: "src/http/router.rs", Anchor: "CODEGEN:HTTP_ROUTES", Insert: "handler.anchor.tmpl"}},
		}},
	}
	return dir, tpl, original
}

func TestGenerate_UsesManifestBuildGateForRustWithoutGoFormatting(t *testing.T) {
	dir, tpl, _ := setupRustProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Result: execx.Result{ExitCode: 0}})

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "handler", "Ride", Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	assertExecutionUnavailable(t, err)
	if len(runner.Calls) != 0 {
		t.Fatalf("denied Rust generation must not run build, calls = %#v", runner.Calls)
	}
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func TestGenerate_ManifestBuildGateFailureRollsBackRust(t *testing.T) {
	dir, tpl, _ := setupRustProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Err: errors.New("cargo check failed")})

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "handler", "Ride", Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	assertExecutionUnavailable(t, err)
	if len(runner.Calls) != 0 {
		t.Fatalf("denied Rust generation must not run build, calls = %#v", runner.Calls)
	}
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
