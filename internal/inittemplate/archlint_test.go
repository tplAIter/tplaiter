package inittemplate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

const lintRulesFixture = "../../testdata/fixtures/lint-rules"

// parseSrc разбирает исходник Go-файла (со строкой package) и возвращает
// (fset, файл) для прогона правил напрямую, без полного рендера.
func parseSrc(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "probe.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v\n%s", err, src)
	}
	return fset, f
}

// TestArchLint_CtxFirst — таблица вариаций правила ctx-first (проверку): ресивер,
// вариадик, ctx вторым → нарушение, без параметров → пропуск, New* →
// исключение, неэкспортируемое → пропуск.
func TestArchLint_CtxFirst(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{
			name: "func ctx first — ok",
			src:  "package p\nimport \"context\"\nfunc DoWork(ctx context.Context, id string) error { _ = ctx; _ = id; return nil }\n",
		},
		{
			name: "method receiver ctx first — ok",
			src:  "package p\nimport \"context\"\ntype T struct{}\nfunc (t *T) Run(ctx context.Context) error { _ = ctx; return nil }\n",
		},
		{
			name:    "method receiver ctx second — violation",
			src:     "package p\nimport \"context\"\ntype T struct{}\nfunc (t *T) Run(id string, ctx context.Context) error { _ = id; _ = ctx; return nil }\n",
			wantErr: true,
		},
		{
			name: "variadic ctx first — ok",
			src:  "package p\nimport \"context\"\nfunc DoAll(ctx ...context.Context) { _ = ctx }\n",
		},
		{
			name:    "variadic non-ctx first — violation",
			src:     "package p\nfunc WithOpts(opts ...string) { _ = opts }\n",
			wantErr: true,
		},
		{
			name:    "ctx second (plain) — violation",
			src:     "package p\nimport \"context\"\nfunc Process(id string, ctx context.Context) error { _ = id; _ = ctx; return nil }\n",
			wantErr: true,
		},
		{
			name: "no params — skip",
			src:  "package p\nfunc NoParams() {}\n",
		},
		{
			name: "New* constructor — excluded regardless of signature",
			src:  "package p\nfunc NewThing(name string) *int { v := 0; _ = name; return &v }\n",
		},
		{
			name: "unexported func — not checked",
			src:  "package p\nfunc process(id string) error { _ = id; return nil }\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset, f := parseSrc(t, tc.src)
			got := checkCtxFirst(fset, f, "probe.go")
			if tc.wantErr && len(got) == 0 {
				t.Fatalf("ожидалось нарушение ctx-first, получено 0")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Fatalf("не ожидалось нарушений, получено: %v", got)
			}
			if tc.wantErr {
				if got[0].Line <= 0 {
					t.Errorf("ожидалась положительная строка нарушения, получено %d", got[0].Line)
				}
				if got[0].RuleID != manifest.LintRuleCtxFirst {
					t.Errorf("RuleID = %q, ожидался %q", got[0].RuleID, manifest.LintRuleCtxFirst)
				}
			}
		})
	}
}

// TestArchLint_NoInit — func init() ловится с координатой строки; файл без
// init зелёный.
func TestArchLint_NoInit(t *testing.T) {
	t.Run("init в domain — нарушение", func(t *testing.T) {
		fset, f := parseSrc(t, "package domain\nfunc init() {\n\t_ = 1\n}\n")
		got := checkNoInit(fset, f, "internal/domain/x.go")
		if len(got) != 1 {
			t.Fatalf("ожидалось 1 нарушение, получено %d: %v", len(got), got)
		}
		if got[0].Line != 2 {
			t.Errorf("ожидалась строка 2 (func init()), получено %d", got[0].Line)
		}
	})
	t.Run("без init — чисто", func(t *testing.T) {
		fset, f := parseSrc(t, "package domain\nfunc DoWork() {}\n")
		if got := checkNoInit(fset, f, "internal/domain/x.go"); len(got) != 0 {
			t.Fatalf("не ожидалось нарушений, получено: %v", got)
		}
	})
}

// TestArchLint_NoPanic — panic в обычной функции (usecase) — нарушение;
// panic в main/init — разрешено (единственное исключение правила).
func TestArchLint_NoPanic(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{
			name:    "panic в usecase — нарушение",
			src:     "package usecase\nfunc Handle() { panic(\"boom\") }\n",
			wantErr: true,
		},
		{
			name: "panic в main — ок",
			src:  "package main\nfunc main() { panic(\"boom\") }\n",
		},
		{
			name: "panic в init — ок",
			src:  "package p\nfunc init() { panic(\"boom\") }\n",
		},
		{
			name: "без panic — чисто",
			src:  "package usecase\nfunc Handle() { _ = 1 }\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset, f := parseSrc(t, tc.src)
			got := checkNoPanic(fset, f, "internal/usecase/x.go")
			if tc.wantErr && len(got) == 0 {
				t.Fatal("ожидалось нарушение no-panic, получено 0")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Fatalf("не ожидалось нарушений, получено: %v", got)
			}
		})
	}
}

// TestArchLint_GeneratedMarker — маркер в первых 5 строках проходит,
// отсутствие/маркер на 6-й строке — нарушение.
func TestArchLint_GeneratedMarker(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"Code generated на 1 строке", "// Code generated by x. DO NOT EDIT.\npackage p\n", true},
		{"DO NOT EDIT без Code generated", "// DO NOT EDIT.\npackage p\n", true},
		{"маркер на 5 строке — граница", "1\n2\n3\n4\n// DO NOT EDIT\npackage p\n", true},
		{"маркер на 6 строке — уже не считается", "1\n2\n3\n4\n5\n// DO NOT EDIT\npackage p\n", false},
		{"без маркера — нарушение", "package p\n// обычный файл\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasGeneratedMarker([]byte(tc.data)); got != tc.want {
				t.Errorf("hasGeneratedMarker = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestArchLint_OptInNoEffect — манифест без секции lint: checkArchLint не
// трогает диск и не возвращает ошибку, даже если outDir не существует.
func TestArchLint_OptInNoEffect(t *testing.T) {
	tpl := &manifest.Template{}
	if err := checkArchLint(tpl, "/nonexistent/path/does-not-matter", []string{"internal/usecase/x.go"}); err != nil {
		t.Fatalf("опциональная секция lint без правил не должна давать эффекта: %v", err)
	}
}

// TestArchLint_MatchLintFiles — сопоставление include/exclude глобов (тот же
// язык, что и files[].paths).
func TestArchLint_MatchLintFiles(t *testing.T) {
	files := []string{
		"internal/usecase/order.go",
		"internal/usecase/order_test.go",
		"internal/infra/db/repo.go",
		"cmd/main.go",
	}
	got := matchLintFiles(files, []string{"internal/usecase/**", "internal/infra/**"}, []string{"**/*_test.go"})
	want := map[string]bool{"internal/usecase/order.go": true, "internal/infra/db/repo.go": true}
	if len(got) != len(want) {
		t.Fatalf("matchLintFiles = %v, want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("неожиданный файл в результате: %q", g)
		}
	}
}

// TestLint_LintRulesFixture_RedThenGreen — e2e реализации проверку: фикстура
// testdata/fixtures/lint-rules с toggle `violations`. [Combos] для
// toggle-группы генерирует и default (violations=false — фикс), и
// all-on/max (violations=true — включённые нарушения) — полный прогон lint-
// template обязан покраснеть с перечнем всех 4 правил, а прогон с фильтром на
// комбо `defaults` ("после исправления") — зелёный.
func TestLint_LintRulesFixture_RedThenGreen(t *testing.T) {
	full, err := Lint(LintOptions{Path: lintRulesFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !full.Failed {
		t.Fatalf("ожидался провал (violations=true в all-on/max):\n%s", failDetails(full))
	}

	var badRow *LintRow
	for i := range full.Rows {
		if !full.Rows[i].OK && strings.Contains(full.Rows[i].Detail, "arch-lint") {
			badRow = &full.Rows[i]
			break
		}
	}
	if badRow == nil {
		t.Fatalf("ожидалась хотя бы одна arch-lint строка с провалом:\n%s", failDetails(full))
	}
	for _, ruleID := range []string{
		manifest.LintRuleCtxFirst,
		manifest.LintRuleNoInit,
		manifest.LintRuleNoPanic,
		manifest.LintRuleGeneratedMarker,
	} {
		if !strings.Contains(badRow.Detail, ruleID) {
			t.Errorf("детали провала не упоминают правило %q:\n%s", ruleID, badRow.Detail)
		}
	}

	fixed, err := Lint(LintOptions{Path: lintRulesFixture, ComboName: "defaults", Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint(defaults): %v", err)
	}
	if fixed.Failed {
		t.Fatalf("комбо defaults (violations=false) должна быть зелёной:\n%s", failDetails(fixed))
	}
}

// TestLint_LintRulesFixture_OptInGlobalTemplatesUnaffected повторно проверяет,
// что опциональность секции lint не портит уже существующую зелёную фикстуру
// single-basic (без секции lint) — быстрый regression-чек рядом с новым кодом.
func TestLint_LintRulesFixture_OptInGlobalTemplatesUnaffected(t *testing.T) {
	res, err := Lint(LintOptions{Path: singleBasicFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("single-basic (без lint) должна остаться зелёной:\n%s", failDetails(res))
	}
}
