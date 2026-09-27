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
	writeFile(t, dir, "go.mod", "module git.example.test/demo\n\ngo 1.26\n")
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

	res, err := GenerateBatch(context.Background(), tpl, []Operation{
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
		{Kind: "pair", Name: "Driver", Fields: opts.Fields, Params: opts.Params},
	}, opts)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	if len(res.Results) != 2 || len(res.CreatedFiles) != 4 || len(res.EditedFiles) != 1 {
		t.Fatalf("unexpected batch result: %#v", res)
	}
	for _, path := range []string{
		"out/ride.txt", "out/driver.txt",
		"out/migrations/00001_ride.txt", "out/migrations/00002_driver.txt",
	} {
		if _, statErr := os.Stat(filepath.Join(dir, path)); statErr != nil {
			t.Errorf("expected %s: %v", path, statErr)
		}
	}
	idx := readFile(t, filepath.Join(dir, "out/index.txt"))
	if !strings.Contains(idx, "gen:pair:ride") || !strings.Contains(idx, "gen:pair:driver") {
		t.Errorf("shared anchor must contain both operations:\n%s", idx)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Name != "go" {
		t.Errorf("build must run exactly once, calls = %#v", runner.Calls)
	}
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
	runner := execx.NewRecordingRunner()
	runner.On("go", []string{"build", "./..."}, execx.Response{Err: errors.New("build failed")})
	opts := multiOpts(dir, mustFields(t, "status:string"))
	opts.NoBuild = false
	opts.Runner = runner

	_, err := GenerateBatch(context.Background(), tpl, []Operation{
		{Kind: "pair", Name: "Ride", Fields: opts.Fields, Params: opts.Params},
		{Kind: "pair", Name: "Driver", Fields: opts.Fields, Params: opts.Params},
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "изменения откачены") {
		t.Fatalf("expected rollback on build failure, got %v", err)
	}
	for _, path := range []string{"out/ride.txt", "out/driver.txt", "out/migrations/00001_ride.txt", "out/migrations/00002_driver.txt"} {
		if _, statErr := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(statErr) {
			t.Errorf("%s must be rolled back, stat err = %v", path, statErr)
		}
	}
	if idx := readFile(t, filepath.Join(dir, "out/index.txt")); idx != pairIndexStub {
		t.Errorf("anchor must be restored:\n%s", idx)
	}
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

	_, err := GenerateBatch(context.Background(), tpl, []Operation{{Kind: "route", Name: "Ride"}, {Kind: "route", Name: "Driver"}}, Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	if len(runner.Calls) != 1 || runner.Calls[0].Name != "/bin/sh" {
		t.Fatalf("Rust batch must run one manifest build-gate, calls = %#v", runner.Calls)
	}
	if runner.Calls[0].Opts.Dir != dir {
		t.Errorf("manifest build-gate Dir = %q, want project root %q", runner.Calls[0].Opts.Dir, dir)
	}
}

func TestGenerateBatch_ManifestBuildGateFailureRollsBackRust(t *testing.T) {
	dir, tpl, original := setupRustBatchProject(t)
	runner := execx.NewRecordingRunner()
	runner.On("/bin/sh", []string{"-c", "cargo check --workspace"}, execx.Response{Err: errors.New("cargo check failed")})

	_, err := GenerateBatch(context.Background(), tpl, []Operation{{Kind: "route", Name: "Ride"}, {Kind: "route", Name: "Driver"}}, Options{
		ProjectRoot: dir, GeneratorsDir: filepath.Join(dir, GeneratorsRelPath), Runner: runner,
	})
	if err == nil || !strings.Contains(err.Error(), "изменения откачены") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	for _, path := range []string{"src/routes/ride.rs", "src/routes/driver.rs"} {
		if _, statErr := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(statErr) {
			t.Errorf("%s must be rolled back, stat err = %v", path, statErr)
		}
	}
	if got := readFile(t, filepath.Join(dir, "src/router.rs")); got != original {
		t.Errorf("Rust anchor must be restored: %q", got)
	}
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

	res, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.CreatedFiles) != 2 {
		t.Fatalf("CreatedFiles = %v (want 2)", res.CreatedFiles)
	}
	if len(res.EditedFiles) != 1 || res.EditedFiles[0] != "out/index.txt" {
		t.Errorf("EditedFiles = %v", res.EditedFiles)
	}

	entity := readFile(t, filepath.Join(dir, "out/order.txt"))
	if !strings.Contains(entity, "entity Order") || !strings.Contains(entity, "customer:text") || !strings.Contains(entity, "amount:double precision") {
		t.Errorf("entity file:\n%s", entity)
	}
	// record-таргет: numbered goose → нет существующих миграций → 00001.
	record := readFile(t, filepath.Join(dir, "out/migrations/00001_order.txt"))
	if !strings.Contains(record, "seq=00001") {
		t.Errorf("record file:\n%s", record)
	}
	idx := readFile(t, filepath.Join(dir, "out/index.txt"))
	if !strings.Contains(idx, "// gen:pair:order") || !strings.Contains(idx, "- order") {
		t.Errorf("index anchor:\n%s", idx)
	}

	// Повтор — ошибка (файлы уже существуют).
	if _, err := Generate(context.Background(), tpl, "pair", "Order", opts); err == nil {
		t.Error("expected duplicate error on repeat")
	}
}

// TestGenerate_Multifile_MigrationSeq: каталог с 00001, 00002 → следующий 00003.
func TestGenerate_Multifile_MigrationSeq(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	writeFile(t, dir, "out/migrations/00001_first.txt", "x\n")
	writeFile(t, dir, "out/migrations/00002_second.txt", "y\n")

	opts := multiOpts(dir, mustFields(t, "a:int"))
	if _, err := Generate(context.Background(), tpl, "pair", "Third", opts); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out/migrations/00003_third.txt")); statErr != nil {
		t.Errorf("expected migration 00003_third.txt: %v", statErr)
	}
}

// TestGenerate_Multifile_TargetWhenGate: target.when гейтит один из таргетов по
// настройкам — при выключенной настройке второй файл не создаётся.
func TestGenerate_Multifile_TargetWhenGate(t *testing.T) {
	dir, tpl := setupMultiProject(t)
	// Гейтим record-таргет по toggle-настройке migrations.
	tpl.Generators[0].Targets[1].When = []string{"migrations=true"}

	// migrations выключена → только entity-файл.
	opts := multiOpts(dir, mustFields(t, "a:int"))
	opts.Values = settings.Values{"migrations": false}
	res, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.CreatedFiles) != 1 || !strings.HasSuffix(res.CreatedFiles[0], "order.txt") {
		t.Fatalf("gated: CreatedFiles = %v (want only entity)", res.CreatedFiles)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out/migrations/00001_order.txt")); !os.IsNotExist(statErr) {
		t.Errorf("gated target must not be created, stat err = %v", statErr)
	}

	// migrations включена → оба файла.
	dir2, tpl2 := setupMultiProject(t)
	tpl2.Generators[0].Targets[1].When = []string{"migrations=true"}
	opts2 := multiOpts(dir2, mustFields(t, "a:int"))
	opts2.Values = settings.Values{"migrations": true}
	res2, err := Generate(context.Background(), tpl2, "pair", "Order", opts2)
	if err != nil {
		t.Fatalf("Generate (enabled): %v", err)
	}
	if len(res2.CreatedFiles) != 2 {
		t.Errorf("enabled: CreatedFiles = %v (want 2)", res2.CreatedFiles)
	}
}

// TestGenerate_Multifile_RollbackOnBuildFailure: второй таргет генерит невалидный
// Go → `go build` падает → откат ПЕРВОГО файла, второго и якоря.
func TestGenerate_Multifile_RollbackOnBuildFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module git.example.test/demo\n\ngo 1.26\n")
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

	_, err := Generate(context.Background(), tpl, "pair", "Order", opts)
	if err == nil || !strings.Contains(err.Error(), "не собирается") {
		t.Fatalf("expected build failure, got %v", err)
	}
	// Откат: первый файл удалён.
	if _, statErr := os.Stat(filepath.Join(dir, "internal/domain/order.go")); !os.IsNotExist(statErr) {
		t.Errorf("first target must be rolled back, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "internal/usecase/order.go")); !os.IsNotExist(statErr) {
		t.Errorf("second target must be rolled back, stat err = %v", statErr)
	}
	// Якорный файл восстановлен (маркера нет).
	reg := readFile(t, filepath.Join(dir, "internal/reg/reg.go"))
	if strings.Contains(reg, "gen:pair:order") {
		t.Errorf("anchor file must be restored:\n%s", reg)
	}
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
// продолжает работать без targets[] — тот же контракт, что и до появления targets[].
func TestGenerate_BackwardCompat_SingleForm(t *testing.T) {
	dir, tpl := setupProject(t) // одиночный use-case генератор
	opts := Options{
		ProjectRoot:   dir,
		GeneratorsDir: filepath.Join(dir, GeneratorsRelPath),
		Values:        settings.Values{},
		NoBuild:       true,
	}
	res, err := Generate(context.Background(), tpl, "use-case", "Bar", opts)
	if err != nil {
		t.Fatalf("Generate single-form: %v", err)
	}
	if len(res.CreatedFiles) != 1 || res.CreatedFiles[0] != "internal/usecase/bar.go" {
		t.Errorf("CreatedFiles = %v", res.CreatedFiles)
	}
	if len(res.EditedFiles) != 1 {
		t.Errorf("EditedFiles = %v", res.EditedFiles)
	}
}
