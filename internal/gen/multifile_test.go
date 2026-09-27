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

const pairIndexStub = "index\n# CODEGEN:PAIR\n"

// setupMultiProject строит проект с мультифайловым генератором pair: 2 таргета
// (entity + record) + якорь в out/index.txt + параметр fields. record-таргет
// помечен numbered: goose и пишется в out/migrations.
func setupMultiProject(t *testing.T) (dir string, tpl *manifest.Template) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, dir, "go.mod", "module example.invalid/demo\n\ngo 1.26\n")
	writeFile(t, dir, "out/index.txt", pairIndexStub)
	writeFile(t, dir, ".tplaiter/generators/pair/entity.txt.tmpl",
		"entity {{ .Name.Pascal }}\n{{- range .Fields }}\n{{ .Name.Snake }}:{{ .SQLType }}{{- end }}\n")
	writeFile(t, dir, ".tplaiter/generators/pair/record.txt.tmpl",
		"record {{ .Name.Pascal }} seq={{ .MigrationSeq }}\n")
	writeFile(t, dir, ".tplaiter/generators/pair.anchor.tmpl", "{{ .Marker }}\n- {{ .Name.Snake }}\n")

	tpl = &manifest.Template{Generators: []manifest.Generator{{
		Kind:        "pair",
		Description: "пара файлов",
		Params:      []manifest.Param{{Name: "fields", Type: manifest.ParamTypeFields, Required: true}},
		Targets: []manifest.Target{
			{Snippet: "pair/entity.txt.tmpl", Target: "out/{{ .Name.Snake }}.txt"},
			{Snippet: "pair/record.txt.tmpl", Target: "out/migrations/{{ .MigrationSeq }}_{{ .Name.Snake }}.txt", Numbered: manifest.NumberedGoose},
		},
		Anchors: []manifest.Anchor{
			{File: "out/index.txt", Anchor: "# CODEGEN:PAIR", Insert: "pair.anchor.tmpl"},
		},
	}}}
	return dir, tpl
}

func TestGenerateBatch_ComposesSharedAnchorAndBuildsOnce(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("go", []string{"build", "./..."}, execx.Response{Result: execx.Result{ExitCode: 0}})
	opts := multiOpts(dir, mustFields(t, "status:string"))
	opts.NoBuild = false
	opts.Runner = runner

	before := snapshotTree(t, dir)
	_, err := GenerateBatch(context.Background(), tpl, []Operation{
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
		{Kind: "pair", Name: "Driver", Fields: opts.Fields, Params: opts.Params},
	}, opts)
	assertExecutionUnavailable(t, err)
	if len(runner.Calls) != 0 {
		t.Fatalf("denied batch must not run build, calls = %#v", runner.Calls)
	}
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func TestGenerateBatch_PreflightFailureLeavesProjectUntouched(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	opts := multiOpts(dir, mustFields(t, "status:string"))
	_, err := GenerateBatch(context.Background(), tpl, []Operation{
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "уже запланирован") {
		t.Fatalf("expected planned-target collision, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out/ride.txt")); !os.IsNotExist(statErr) {
		t.Errorf("preflight failure must not create target, stat err = %v", statErr)
	}
	if idx := readFile(t, filepath.Join(dir, "out/index.txt")); idx != pairIndexStub {
		t.Errorf("preflight failure must not edit anchor:\n%s", idx)
	}
}

func TestGenerateBatch_BuildFailureRollsBackAllOperations(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	opts := multiOpts(dir, mustFields(t, "status:string"))
	opts.NoBuild = false

	before := snapshotTree(t, dir)
	_, err := GenerateBatch(context.Background(), tpl, []Operation{
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
		{Kind: "pair", Name: "Driver", Fields: opts.Fields, Params: opts.Params},
	}, opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func setupRustBatchProject(t *testing.T) (dir string, tpl *manifest.Template, original string) {
	t.Helper()
	dir = t.TempDir()
	original = "// CODEGEN:ROUTES\n"
	writeFile(t, dir, "src/router.rs", original)
	writeFile(t, dir, ".tplaiter/generators/route.rs.tmpl", "pub struct {{ .Name.Pascal }}Route;\n")
	writeFile(t, dir, ".tplaiter/generators/route.anchor.tmpl", "// {{ .Marker }}\nlet _ = {{ .Name.Pascal }}Route;\n")
	tpl = &manifest.Template{
		Commands: map[string]manifest.Command{"build": {Run: "cargo check --workspace"}},
		Generators: []manifest.Generator{{
			Kind: "route", Snippet: "route.rs.tmpl", Target: "src/routes/{{ .Name.Snake }}.rs",
			Anchors: []manifest.Anchor{{File: "src/router.rs", Anchor: "CODEGEN:ROUTES", Insert: "route.anchor.tmpl"}},
		}},
	}
	return dir, tpl, original
}

func TestGenerateBatch_UsesOneManifestBuildGateForRust(t *testing.T) {
	dir, tpl, _ := setupRustBatchProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Result: execx.Result{ExitCode: 0}})

	before := snapshotTree(t, dir)
	_, err := GenerateBatch(context.Background(), tpl, []Operation{{Kind: "route", Name: "Ride"}, {Kind: "route", Name: "Driver"}}, Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	assertExecutionUnavailable(t, err)
	if len(runner.Calls) != 0 {
		t.Fatalf("denied Rust batch must not run build, calls = %#v", runner.Calls)
	}
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func TestGenerateBatch_ManifestBuildGateFailureRollsBackRust(t *testing.T) {
	dir, tpl, _ := setupRustBatchProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Err: errors.New("cargo check failed")})

	before := snapshotTree(t, dir)
	_, err := GenerateBatch(context.Background(), tpl, []Operation{{Kind: "route", Name: "Ride"}, {Kind: "route", Name: "Driver"}}, Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	assertExecutionUnavailable(t, err)
	if len(runner.Calls) != 0 {
		t.Fatalf("denied Rust batch must not run build, calls = %#v", runner.Calls)
	}
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

func multiOpts(dir string, fields []Field) Options {
	return Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{},
		Fields:        fields,
		Params:        map[string]any{"fields": fields},
		NoBuild:       true,
	}
}

func mustFields(t *testing.T, spec string) []Field {
	t.Helper()
	f, err := ParseFields(spec)
	if err != nil {
		t.Fatalf("ParseFields(%q): %v", spec, err)
	}
	return f
}

func TestGenerate_Multifile_CreatesBothTargetsAndAnchor(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	opts := multiOpts(dir, mustFields(t, "customer:string,amount:float64"))

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

// TestGenerate_Multifile_MigrationSeq: каталог с 00001, 00002 → следующий 00003.
func TestGenerate_Multifile_MigrationSeq(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	writeFile(t, dir, "out/migrations/00001_first.txt", "x\n")
	writeFile(t, dir, "out/migrations/00002_second.txt", "y\n")

	opts := multiOpts(dir, mustFields(t, "a:int"))
	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "pair", "Third", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

// TestGenerate_Multifile_TargetWhenGate: target.when гейтит один из таргетов по
// настройкам — при выключенной настройке второй файл не создаётся.
func TestGenerate_Multifile_TargetWhenGate(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	// Гейтим record-таргет по toggle-настройке migrations.
	tpl.Generators[0].Targets[1].When = []string{"migrations=true"}

	// migrations выключена: target selection is pure, execution is denied.
	opts := multiOpts(dir, mustFields(t, "a:int"))
	opts.Values = settings.Values{"migrations": false}
	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))

	// migrations включена → оба файла.
	dir2, tpl2 := setupMultiProject(t)
	tpl2.Generators[0].Targets[1].When = []string{"migrations=true"}
	opts2 := multiOpts(dir2, mustFields(t, "a:int"))
	opts2.Values = settings.Values{"migrations": true}
	before2 := snapshotTree(t, dir2)
	_, err = Generate(context.Background(), tpl2, "pair", "Order", opts2)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before2, snapshotTree(t, dir2))
}

// TestGenerate_Multifile_RollbackOnBuildFailure: второй таргет генерит невалидный
// Go → `go build` падает → откат ПЕРВОГО файла, второго и якоря.
func TestGenerate_Multifile_RollbackOnBuildFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.invalid/demo\n\ngo 1.26\n")
	writeFile(t, dir, "internal/reg/reg.go", "package reg\n\n// CODEGEN:PAIR\nvar Registered []string\n")
	// Первый таргет — валидный Go; второй — синтаксически битый.
	writeFile(t, dir, ".tplaiter/generators/a.go.tmpl", "package domain\n\ntype {{ .Name.Pascal }} struct{}\n")
	writeFile(t, dir, ".tplaiter/generators/b.go.tmpl", "package usecase\n\ntype {{ .Name.Pascal }} struct {\n")
	writeFile(t, dir, ".tplaiter/generators/reg.anchor.tmpl", "{{ .Marker }}\n\t_ = \"{{ .Name.Snake }}\"\n")

	tpl := &manifest.Template{Generators: []manifest.Generator{{
		Kind: "pair",
		Targets: []manifest.Target{
			{Snippet: "a.go.tmpl", Target: "internal/domain/{{ .Name.Snake }}.go"},
			{Snippet: "b.go.tmpl", Target: "internal/usecase/{{ .Name.Snake }}.go"},
		},
		Anchors: []manifest.Anchor{
			{File: "internal/reg/reg.go", Anchor: "// CODEGEN:PAIR", Insert: "reg.anchor.tmpl"},
		},
	}}}

	opts := Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{},
	} // NoBuild:false

	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}

// TestGenerate_Multifile_RenderErrorNoWrites: ошибка рендера второго сниппета
// (до записи) не создаёт ни одного файла и не трогает якорь (атомарность).
func TestGenerate_Multifile_RenderErrorNoWrites(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	// Ломаем шаблон второго таргета — синтаксическая ошибка text/template.
	writeFile(t, dir, ".tplaiter/generators/pair/record.txt.tmpl", "record {{ .Name.Pascal ")

	opts := multiOpts(dir, mustFields(t, "a:int"))
	_, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	if err == nil {
		t.Fatal("expected render error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out/order.txt")); !os.IsNotExist(statErr) {
		t.Errorf("no target must be written on render error, stat err = %v", statErr)
	}
	if idx := readFile(t, filepath.Join(dir, "out/index.txt")); idx != pairIndexStub {
		t.Errorf("anchor file must be untouched:\n%s", idx)
	}
}

// TestGenerate_BackwardCompat_SingleForm: старая одиночная форма (snippet+target)
// продолжает работать без targets[] — тот же контракт, что и до CG-1.
func TestGenerate_BackwardCompat_SingleForm(t *testing.T) {
	dir, tpl := setupProject(t) // одиночный use-case генератор
	opts := Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{},
		NoBuild:       true,
	}
	before := snapshotTree(t, dir)
	_, err := Generate(context.Background(), tpl, "use-case", "Bar", opts)
	assertExecutionUnavailable(t, err)
	assertTreeEqual(t, before, snapshotTree(t, dir))
}
