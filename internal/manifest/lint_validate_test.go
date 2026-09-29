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
		t.Fatalf("an empty lint section must not affect validation: %v", err)
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
			want:  "rule id is required",
		},
		{
			name:  "unknown id",
			rules: []LintRule{{ID: "no-such-rule", Paths: []string{"internal/**"}}},
			want:  "unknown rule id",
		},
		{
			name:  "empty paths",
			rules: []LintRule{{ID: LintRuleNoInit}},
			want:  "checks nothing",
		},
		{
			name:  "bad glob in paths",
			rules: []LintRule{{ID: LintRuleNoInit, Paths: []string{"internal/[unclosed"}}},
			want:  "invalid glob",
		},
		{
			name:  "bad glob in exclude",
			rules: []LintRule{{ID: LintRuleNoInit, Paths: []string{"internal/**"}, Exclude: []string{"[unclosed"}}},
			want:  "invalid glob",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := baseTemplateForLint()
			tpl.Lint = LintConfig{Rules: tc.rules}
			err := tpl.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not contain %q:\n%v", tc.want, err)
			}
		})
	}
}
