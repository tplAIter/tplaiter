package manifest

import (
	"strings"
	"testing"
)

// baseTemplate is a minimal valid manifest (without lint) for table tests of the
// lint section; it isolates the check from the rest of the validator.
func baseTemplateForLint() *Template {
	return &Template{
		APIVersion: APIVersion,
		Kind:       KindTemplate,
		Metadata:   TemplateMeta{Name: "lint-fixture", Version: "0.1.0"},
		Engine:     Engine{Type: "gotemplate"},
	}
}

func TestValidate_Lint_OptInNoEffect(t *testing.T) {
	tpl := baseTemplateForLint()
	// Lint is unset (the zero value), so the validator must not add lint issues.
	if err := tpl.Validate(); err != nil {
		t.Fatalf("пустая секция lint не должна влиять на валидацию: %v", err)
	}
}

func TestValidate_Lint_Rules(t *testing.T) {
	tests := []struct {
		name  string
		rules []LintRule
		want  string // substring in the aggregate error; empty means valid
	}{
		{
			name: "valid ctx-first",
			rules: []LintRule{
				{ID: LintRuleCtxFirst, Paths: []string{"internal/usecase/**"}, Exclude: []string{"**/*_test.go"}},
			},
		},
		{
			name: "valid all known ids",
			rules: []LintRule{
				{ID: LintRuleCtxFirst, Paths: []string{"internal/usecase/**"}},
				{ID: LintRuleNoInit, Paths: []string{"internal/domain/**"}},
				{ID: LintRuleGeneratedMarker, Paths: []string{"internal/api/openapi/**"}},
				{ID: LintRuleNoPanic, Paths: []string{"internal/**"}},
			},
		},
		{
			name:  "missing id",
			rules: []LintRule{{Paths: []string{"internal/**"}}},
			want:  "id правила обязателен",
		},
		{
			name:  "unknown id",
			rules: []LintRule{{ID: "no-such-rule", Paths: []string{"internal/**"}}},
			want:  "неизвестный id правила",
		},
		{
			name:  "empty paths",
			rules: []LintRule{{ID: LintRuleNoInit}},
			want:  "ничего не проверяет",
		},
		{
			name:  "bad glob in paths",
			rules: []LintRule{{ID: LintRuleNoInit, Paths: []string{"internal/[unclosed"}}},
			want:  "некорректный glob",
		},
		{
			name:  "bad glob in exclude",
			rules: []LintRule{{ID: LintRuleNoInit, Paths: []string{"internal/**"}, Exclude: []string{"[unclosed"}}},
			want:  "некорректный glob",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := baseTemplateForLint()
			tpl.Lint = LintConfig{Rules: tc.rules}
			err := tpl.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ожидалась валидность, получено: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка не содержит %q:\n%v", tc.want, err)
			}
		})
	}
}
