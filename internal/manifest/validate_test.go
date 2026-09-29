package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate_Full_Clean(t *testing.T) {
	tpl, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatalf("the full manifest must be valid, got: %v", err)
	}
}

func TestValidate_InvalidFixtures(t *testing.T) {
	tests := []struct {
		file string
		want string // substring expected in the aggregate error
	}{
		{"invalid/dup_id.yaml", "duplicate group id"},
		{"invalid/planned_default.yaml", "planned option"},
		{"invalid/bad_condition.yaml", "non-existent group"},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			tpl, err := LoadTemplate(fixture(tc.file))
			if err != nil {
				t.Fatalf("LoadTemplate: %v", err)
			}
			err = tpl.Validate()
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not contain %q:\n%v", tc.want, err)
			}
		})
	}
}

func TestValidate_BadConditionSyntax(t *testing.T) {
	tpl, err := LoadTemplate(fixture("invalid/bad_condition.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	err = tpl.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	// The second files rule, `when: "database"`, has a condition syntax error.
	if !strings.Contains(err.Error(), "has no operator") {
		t.Errorf("expected a condition syntax error:\n%v", err)
	}
}

func TestValidate_Aggregates(t *testing.T) {
	// A manifest with several independent problems: all must appear in the report.
	src := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata:
  name: Bad_Name
  version: not-semver
settings:
  - group: db
    type: bogus
    default: none
    options:
      - id: x
files:
  - when: "missing=1"
    paths: ["a["]
generators:
  - kind: g
    snippet: ""
    target: ""
`
	tpl, err := ParseTemplate([]byte(src))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	var verr ValidationErrors
	if !errors.As(tpl.Validate(), &verr) {
		t.Fatalf("Validate did not return ValidationErrors: %T", tpl.Validate())
	}
	checks := []string{
		"metadata.name",
		"metadata.version",
		"unknown type",
		"non-existent group",
		"invalid glob",
		"snippet",
		"target",
	}
	agg := verr.Error()
	for _, c := range checks {
		if !strings.Contains(agg, c) {
			t.Errorf("aggregated error does not contain %q:\n%s", c, agg)
		}
	}
	if len(verr) < len(checks) {
		t.Errorf("expected >= %d problems, got %d", len(checks), len(verr))
	}
}

func TestValidate_Generator_MultifileValid(t *testing.T) {
	src := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: { name: g, version: 1.0.0 }
settings:
  - group: workflow
    type: select
    default: none
    options:
      - id: none
      - id: temporal
generators:
  - kind: crud
    params:
      - { name: fields, type: fields, required: true, description: "fields" }
      - { name: with-list, type: bool, default: true }
    targets:
      - { snippet: g/entity.tmpl, target: "internal/domain/{{ .Name.Snake }}.go" }
      - { snippet: g/activity.tmpl, target: "internal/activity/{{ .Name.Snake }}.go", when: ["workflow=temporal"] }
      - { snippet: g/mig.tmpl, target: "db/{{ .MigrationSeq }}_{{ .Name.Snake }}.sql", numbered: goose }
    anchors:
      - { file: internal/app.go, anchor: "//X", insert: g/anchor.tmpl }
`
	tpl, err := ParseTemplate([]byte(src))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatalf("a multi-file generator must be valid: %v", err)
	}
}

func TestValidate_Generator_Errors(t *testing.T) {
	tests := []struct {
		name, generators, want string
	}{
		{
			"both_forms",
			"  - { kind: k, snippet: a.tmpl, target: t, targets: [{ snippet: b.tmpl, target: u }] }",
			"both single-file form",
		},
		{
			"target_missing_snippet",
			"  - { kind: k, targets: [{ target: u }] }",
			"target snippet is required",
		},
		{
			"bad_numbered",
			"  - { kind: k, targets: [{ snippet: a.tmpl, target: u, numbered: bogus }] }",
			"unknown numbering strategy",
		},
		{
			"bad_param_type",
			"  - { kind: k, snippet: a.tmpl, target: t, params: [{ name: x, type: money }] }",
			"unknown parameter type",
		},
		{
			"dup_param",
			"  - { kind: k, snippet: a.tmpl, target: t, params: [{ name: x, type: int }, { name: x, type: string }] }",
			"duplicate parameter name",
		},
		{
			"bad_param_name",
			"  - { kind: k, snippet: a.tmpl, target: t, params: [{ name: \"1x\", type: int }] }",
			"invalid parameter name",
		},
		{
			"bad_param_pattern",
			"  - { kind: k, snippet: a.tmpl, target: t, params: [{ name: table, type: string, pattern: \"([a-z\" }] }",
			"invalid regexp",
		},
		{
			"unsupported_param_pattern_type",
			"  - { kind: k, snippet: a.tmpl, target: t, params: [{ name: enabled, type: bool, pattern: \"^true$\" }] }",
			"pattern is only supported",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := "apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata: { name: g, version: 1.0.0 }\ngenerators:\n" + tc.generators + "\n"
			tpl, err := ParseTemplate([]byte(src))
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			err = tpl.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestValidate_MultiselectSubsetDefault(t *testing.T) {
	src := `apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: { name: ms, version: 1.0.0 }
settings:
  - group: brokers
    type: multiselect
    default: [kafka, nosuch]
    options:
      - id: kafka
      - id: rabbitmq
`
	tpl, err := ParseTemplate([]byte(src))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	err = tpl.Validate()
	if err == nil || !strings.Contains(err.Error(), "not found among options") {
		t.Fatalf("expected an error about a missing option in default, got: %v", err)
	}
}
