package gen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// TestNewContextDerivations проверяет производные имена (Pascal/Camel/Snake/Kebab).
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

	// OR-семантика: истинности ОДНОГО условия списка достаточно.
	ok, err = evalGate([]string{"brokers=rabbitmq", "brokers=kafka"}, values)
	if err != nil || !ok {
		t.Errorf("expected OR semantics to make this available: ok=%v err=%v", ok, err)
	}

	ok, err = evalGate([]string{"brokers=rabbitmq"}, values)
	if err != nil || ok {
		t.Errorf("expected unavailable: ok=%v err=%v", ok, err)
	}
}

// writeFile создаёт файл с содержимым content, создавая недостающие каталоги.
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

const appGoStub = `package app

import (
	"log/slog"

	"git.example.test/demo/internal/usecase"
)

func New(logger *slog.Logger) error {
	_ = usecase.Placeholder
	// CODEGEN:WIRING — сюда tplater gen use-case добавляет новые сценарии.
	return nil
}
`

const usecaseSnippetTmpl = `// Package usecase содержит бизнес-сценарии сервиса.
package usecase

// Placeholder существует, чтобы пакет не был пустым до первого gen.
var Placeholder int

// {{ .Name.Pascal }}UseCase — сценарий {{ .Name.Pascal }}.
type {{ .Name.Pascal }}UseCase struct{}
`

const usecaseWiringTmpl = `	{{ .Marker }}
	_ = usecase.{{ .Name.Pascal }}UseCase{}
`

// setupProject создаёт минимальный проект: go.mod, app.go с якорем CODEGEN:WIRING,
// пакет usecase, и каталог .tplaiter/generators со сниппетами use-case.
func setupProject(t *testing.T) (dir string, tpl *manifest.Template) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, dir, "go.mod", "module git.example.test/demo\n\ngo 1.26\n")
	writeFile(t, dir, "internal/app/app.go", appGoStub)
	writeFile(t, dir, ".tplaiter/generators/use-case.go.tmpl", usecaseSnippetTmpl)
	writeFile(t, dir, ".tplaiter/generators/use-case.anchor.tmpl", usecaseWiringTmpl)

	tpl = &manifest.Template{
		Generators: []manifest.Generator{
			{
				Kind:        "use-case",
				Description: "Сценарий",
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

	res, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.CreatedFiles) != 1 || res.CreatedFiles[0] != "internal/usecase/foo.go" {
		t.Errorf("CreatedFiles = %v", res.CreatedFiles)
	}
	if len(res.EditedFiles) != 1 || res.EditedFiles[0] != "internal/app/app.go" {
		t.Errorf("EditedFiles = %v", res.EditedFiles)
	}

	created := readFile(t, filepath.Join(dir, "internal/usecase/foo.go"))
	if !strings.Contains(created, "FooUseCase") {
		t.Errorf("created file missing FooUseCase:\n%s", created)
	}

	app := readFile(t, filepath.Join(dir, "internal/app/app.go"))
	if !strings.Contains(app, "// gen:use-case:foo") {
		t.Errorf("marker not inserted into app.go:\n%s", app)
	}
	if !strings.Contains(app, "FooUseCase{}") {
		t.Errorf("wiring block not inserted into app.go:\n%s", app)
	}
	// Маркер должен идти перед строкой якоря.
	if strings.Index(app, "gen:use-case:foo") > strings.Index(app, "CODEGEN:WIRING") {
		t.Errorf("marker must precede anchor line:\n%s", app)
	}

	// Повтор с тем же именем — ошибка (файл уже существует).
	if _, err := Generate(context.Background(), tpl, "use-case", "Foo", opts); err == nil {
		t.Error("expected error on duplicate gen (target file exists)")
	}
}

func TestGenerate_UnknownKind(t *testing.T) {
	dir, tpl := setupProject(t)
	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), NoBuild: true}
	_, err := Generate(context.Background(), tpl, "nope", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "неизвестный вид") {
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

	// С включённым брокером генерация проходит.
	opts.Values = settings.Values{"brokers": []string{"kafka"}}
	if _, err := Generate(context.Background(), tpl, "kafka-consumer", "Foo", opts); err != nil {
		t.Errorf("expected success once brokers=kafka: %v", err)
	}
}

func TestGenerate_MissingAnchorFails(t *testing.T) {
	dir, tpl := setupProject(t)
	// Портим app.go — якоря там больше нет.
	writeFile(t, dir, "internal/app/app.go", "package app\n")

	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), NoBuild: true}
	_, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "якорь") {
		t.Errorf("expected anchor-not-found error, got %v", err)
	}
	// Ничего не должно быть создано при ошибке подготовки якорей (до записи).
	if _, statErr := os.Stat(filepath.Join(dir, "internal/usecase/foo.go")); statErr == nil {
		t.Error("target file must not be created when anchor preparation fails")
	}
}

// TestGenerate_RollbackOnBuildFailure проверяет полный откат (созданный файл
// удалён, app.go восстановлен) при провале `go build ./...` вызванном
// синтаксической ошибкой в сниппете.
func TestGenerate_RollbackOnBuildFailure(t *testing.T) {
	dir, tpl := setupProject(t)
	// Ломаем сниппет: незакрытая скобка структуры.
	writeFile(t, dir, ".tplaiter/generators/use-case.go.tmpl", "package usecase\n\ntype {{ .Name.Pascal }}UseCase struct {\n")

	opts := Options{ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath)} // NoBuild: false (по умолчанию)

	_, err := Generate(context.Background(), tpl, "use-case", "Foo", opts)
	if err == nil || !strings.Contains(err.Error(), "не собирается") {
		t.Fatalf("expected build failure error, got %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(dir, "internal/usecase/foo.go")); !os.IsNotExist(statErr) {
		t.Errorf("expected created file to be rolled back, stat err = %v", statErr)
	}
	app := readFile(t, filepath.Join(dir, "internal/app/app.go"))
	if app != appGoStub {
		t.Errorf("expected app.go to be restored to original content, got:\n%s", app)
	}
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

	_, err := Generate(context.Background(), tpl, "handler", "Ride", Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Name != "/bin/sh" {
		t.Fatalf("Rust must run only manifest build-gate, calls = %#v", runner.Calls)
	}
	if runner.Calls[0].Opts.Dir != dir {
		t.Errorf("manifest build-gate Dir = %q, want project root %q", runner.Calls[0].Opts.Dir, dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "src/http/ride.rs")); err != nil {
		t.Fatalf("generated Rust file: %v", err)
	}
}

func TestGenerate_ManifestBuildGateFailureRollsBackRust(t *testing.T) {
	dir, tpl, original := setupRustProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Err: errors.New("cargo check failed")})

	_, err := Generate(context.Background(), tpl, "handler", "Ride", Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	if err == nil || !strings.Contains(err.Error(), "изменения откачены") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "src/http/ride.rs")); !os.IsNotExist(statErr) {
		t.Errorf("generated Rust file must be rolled back, stat err = %v", statErr)
	}
	if got := readFile(t, filepath.Join(dir, "src/http/router.rs")); got != original {
		t.Errorf("Rust anchor must be restored: %q", got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
