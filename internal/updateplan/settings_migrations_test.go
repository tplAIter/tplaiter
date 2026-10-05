package updateplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

func TestSignedAnswerMigrations(t *testing.T) {
	source := &manifest.Template{Metadata: manifest.TemplateMeta{Version: "1.0.0"}}
	target := &manifest.Template{Metadata: manifest.TemplateMeta{Version: "3.0.0"}, Migrations: []migrations.Migration{
		{ID: "rename", From: "1.0.0", To: "2.0.0", Phase: "after", Settings: migrations.MigrationSettings{Rename: map[string]string{"old": "new", "a": "b", "b": "a"}}},
		{ID: "delete", From: "2.0.0", To: "3.0.0", Phase: "before", Settings: migrations.MigrationSettings{Delete: []string{"trash"}}},
	}}
	answers := map[string]stateledger.Answer{"old": {Value: true, Source: "default"}, "a": {Value: "alpha", Source: "user"}, "b": {Value: "beta", Source: "legacy"}, "trash": {Value: "gone", Source: "user"}, "keep": {Value: false, Source: "default"}}
	original := map[string]stateledger.Answer{}
	for k, v := range answers {
		original[k] = v
	}
	plan, out, err := planAnswerMigrations(source, target, nil, answers)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(answers, original) {
		t.Fatal("input changed")
	}
	if out["new"] != (stateledger.Answer{Value: true, Source: "migration"}) || out["a"].Value != "beta" || out["b"].Value != "alpha" || out["keep"] != answers["keep"] {
		t.Fatalf("transformed records: %+v", out)
	}
	if _, ok := out["trash"]; ok {
		t.Fatal("deleted record resurrected")
	}
	if _, ok := out["old"]; ok {
		t.Fatal("rename source retained")
	}
	if _, _, err := planAnswerMigrations(target, target, plan.Ledger.After, out); err != nil {
		t.Fatal(err)
	}
	answers["new"] = stateledger.Answer{Value: "occupied", Source: "user"}
	if _, _, err := planAnswerMigrations(source, target, nil, answers); err == nil {
		t.Fatal("occupied target accepted")
	}
	target.Migrations[0].Steps = []migrations.MigrationStep{{Run: "must-not-execute"}}
	if _, _, err := planAnswerMigrations(source, target, nil, original); !errors.Is(err, migrations.ErrExecutionUnauthorized) {
		t.Fatalf("executable not typed refusal: %v", err)
	}
}

func TestMigrationInactiveSnapshotAndActiveDefault(t *testing.T) {
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: answers, version: 2.0.0}
settings:
  - group: parent
    type: select
    default: off
    options:
      - id: off
      - id: on
        settings:
          - group: renamed
            type: toggle
            default: false
  - group: active
    type: toggle
    default: false
`))
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]stateledger.Answer{"parent": {Value: "off", Source: "user"}, "renamed": {Value: true, Source: "migration"}, "active": {Value: true, Source: "default"}}
	resolved, err := ResolveSettingsAnswers(tpl, answers, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := settingsAnswerAfterimages(tpl, answers, resolved.Values, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["renamed"] != answers["renamed"] || resolved.ActiveValues["renamed"] != false || out["active"].Value != false {
		t.Fatalf("snapshots/defaults %+v %+v", out, resolved)
	}
}

func TestNoMigrationReportWireCompatibility(t *testing.T) {
	// The pre-lane report has no migrations property. Its exact JSON and hence
	// domain-digested receipt framing must be unchanged when the new field is nil.
	raw, err := json.Marshal(Report{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"migrations"`)) {
		t.Fatal("legacy report hash input gained a field")
	}
	source := &manifest.Template{Metadata: manifest.TemplateMeta{Version: "1.0.0"}}
	answers := map[string]stateledger.Answer{"keep": {Value: "ok", Source: "default"}}
	plan, out, err := planAnswerMigrations(source, source, []byte(`{"version":1,"applied":[]}`), answers)
	if err != nil || plan != nil || !reflect.DeepEqual(answers, out) {
		t.Fatalf("ordinary migration framing changed: %v", err)
	}
}

func TestDeprecatedSignedRecordTransformRetainsOnlyMovedRecords(t *testing.T) {
	plan := &migrations.Plan{Before: []migrations.PlannedMigration{{Order: 0, Settings: migrations.MigrationSettings{Rename: map[string]string{"old": "retired"}, Delete: []string{"removed"}}}}}
	moved, err := migrateAnswerRecords(plan, map[string]stateledger.Answer{"old": {Value: false, Source: "default"}, "removed": {Value: "x", Source: "user"}})
	if err != nil {
		t.Fatal(err)
	}
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{{Group: "retired", Type: manifest.TypeToggle, Deprecated: true}, {Group: "removed", Type: manifest.TypeString, Deprecated: true}}}
	resolved, err := ResolveSettingsAnswers(tpl, moved, nil)
	if err != nil {
		t.Fatal(err)
	}
	if moved["retired"].Source != "migration" || resolved.Values["retired"] != false {
		t.Fatal("signed transform retention lost")
	}
	if _, ok := resolved.Values["removed"]; ok {
		t.Fatal("deleted record resurrected")
	}
}
