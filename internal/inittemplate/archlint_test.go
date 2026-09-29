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

// parseSrc parses a Go source file (with a package line) and returns (fset, file)
// for running rules directly without a full render.
func parseSrc(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "probe.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v\n%s", err, src)
	}
	return fset, f
}

// TestArchLint_CtxFirst — ctx-first rule variations: receiver, variadic, ctx
// second → violation; no parameters → skip; New* → exclusion; unexported → skip.
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
				t.Fatalf("expected a ctx-first violation, got 0")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Fatalf("expected no violations, got: %v", got)
			}
			if tc.wantErr {
				if got[0].Line <= 0 {
					t.Errorf("expected a positive violation line, got %d", got[0].Line)
				}
				if got[0].RuleID != manifest.LintRuleCtxFirst {
					t.Errorf("RuleID = %q, expected %q", got[0].RuleID, manifest.LintRuleCtxFirst)
				}
			}
		})
	}
}

// TestArchLint_NoInit — func init() is caught with a line coordinate; a file
// without init passes.
func TestArchLint_NoInit(t *testing.T) {
	t.Run("init in domain is a violation", func(t *testing.T) {
		fset, f := parseSrc(t, "package domain\nfunc init() {\n\t_ = 1\n}\n")
		got := checkNoInit(fset, f, "internal/domain/x.go")
		if len(got) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(got), got)
		}
		if got[0].Line != 2 {
			t.Errorf("expected line 2 (func init()), got %d", got[0].Line)
		}
	})
	t.Run("no init is clean", func(t *testing.T) {
		fset, f := parseSrc(t, "package domain\nfunc DoWork() {}\n")
		if got := checkNoInit(fset, f, "internal/domain/x.go"); len(got) != 0 {
			t.Fatalf("expected no violations, got: %v", got)
		}
	})
}

// TestArchLint_NoPanic — panic in an ordinary function (usecase) is a violation;
// panic in main/init is allowed (the rule's sole exception).
func TestArchLint_NoPanic(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{
			name:    "panic in usecase is a violation",
			src:     "package usecase\nfunc Handle() { panic(\"boom\") }\n",
			wantErr: true,
		},
		{
			name: "panic in main is ok",
			src:  "package main\nfunc main() { panic(\"boom\") }\n",
		},
		{
			name: "panic in init is ok",
			src:  "package p\nfunc init() { panic(\"boom\") }\n",
		},
		{
			name: "no panic is clean",
			src:  "package usecase\nfunc Handle() { _ = 1 }\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset, f := parseSrc(t, tc.src)
			got := checkNoPanic(fset, f, "internal/usecase/x.go")
			if tc.wantErr && len(got) == 0 {
				t.Fatal("expected a no-panic violation, got 0")
			}
			if !tc.wantErr && len(got) != 0 {
				t.Fatalf("expected no violations, got: %v", got)
			}
		})
	}
}

// TestArchLint_GeneratedMarker — a marker in the first 5 lines passes; missing
// or a marker on line 6 is a violation.
func TestArchLint_GeneratedMarker(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"Code generated on line 1", "// Code generated by x. DO NOT EDIT.\npackage p\n", true},
		{"DO NOT EDIT without Code generated", "// DO NOT EDIT.\npackage p\n", true},
		{"marker on line 5 is the boundary", "1\n2\n3\n4\n// DO NOT EDIT\npackage p\n", true},
		{"marker on line 6 no longer counts", "1\n2\n3\n4\n5\n// DO NOT EDIT\npackage p\n", false},
		{"no marker is a violation", "package p\n// regular file\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasGeneratedMarker([]byte(tc.data)); got != tc.want {
				t.Errorf("hasGeneratedMarker = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestArchLint_OptInNoEffect — manifest without lint: checkArchLint neither
// touches disk nor returns an error, even when outDir does not exist.
func TestArchLint_OptInNoEffect(t *testing.T) {
	tpl := &manifest.Template{}
	if err := checkArchLint(tpl, "/nonexistent/path/does-not-matter", []string{"internal/usecase/x.go"}); err != nil {
		t.Fatalf("an optional lint section without rules must have no effect: %v", err)
	}
}

// TestArchLint_MatchLintFiles — include/exclude glob matching (same language as
// files[].paths).
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
			t.Errorf("unexpected file in the result: %q", g)
		}
	}
}

// TestLint_LintRulesFixture_RedThenGreen — e2e check: the
// testdata/fixtures/lint-rules fixture has a `violations` toggle. [Combos]
// generates default (violations=false, fixed) and all-on/max (violations=true,
// enabled violations); the full lint-template run must report all 4 rules,
// while filtering to `defaults` ("after fixing") passes.
func TestLint_LintRulesFixture_RedThenGreen(t *testing.T) {
	full, err := Lint(LintOptions{Path: lintRulesFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !full.Failed {
		t.Fatalf("expected failure (violations=true in all-on/max):\n%s", failDetails(full))
	}

	var badRow *LintRow
	for i := range full.Rows {
		if !full.Rows[i].OK && strings.Contains(full.Rows[i].Detail, "arch-lint") {
			badRow = &full.Rows[i]
			break
		}
	}
	if badRow == nil {
		t.Fatalf("expected at least one failing arch-lint row:\n%s", failDetails(full))
	}
	for _, ruleID := range []string{
		manifest.LintRuleCtxFirst,
		manifest.LintRuleNoInit,
		manifest.LintRuleNoPanic,
		manifest.LintRuleGeneratedMarker,
	} {
		if !strings.Contains(badRow.Detail, ruleID) {
			t.Errorf("failure details do not mention rule %q:\n%s", ruleID, badRow.Detail)
		}
	}

	fixed, err := Lint(LintOptions{Path: lintRulesFixture, ComboName: "defaults", Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint(defaults): %v", err)
	}
	if fixed.Failed {
		t.Fatalf("combo defaults (violations=false) must be green:\n%s", failDetails(fixed))
	}
}

// TestLint_LintRulesFixture_OptInGlobalTemplatesUnaffected rechecks that the
// optional lint section does not break the existing passing single-basic fixture
// (without lint), a quick regression check beside the new code.
func TestLint_LintRulesFixture_OptInGlobalTemplatesUnaffected(t *testing.T) {
	res, err := Lint(LintOptions{Path: singleBasicFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("single-basic (no lint) must stay green:\n%s", failDetails(res))
	}
}
