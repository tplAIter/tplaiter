package updateplan

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

func answerPolicyTemplate(t *testing.T) *manifest.Template {
	t.Helper()
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: answers, version: 1.0.0, description: fixture}
engine: {type: gotemplate, root: files}
settings:
 - {group: label, title: Label, type: string, default: alpha}
 - {group: enabled, title: Enabled, type: toggle, default: false}
 - group: features
   title: Features
   type: multiselect
   default: []
   options:
    - {id: a, title: A, requires: ["enabled=true"]}
 - group: parent
   title: Parent
   type: select
   default: off
   options:
    - {id: off, title: Off}
    - id: on
      title: On
      settings:
       - {group: child, title: Child, type: string, default: initial}
`))
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestNativeAnswersOriginControlsDefaultEqualRequires(t *testing.T) {
	tpl := answerPolicyTemplate(t)
	for _, source := range []string{"default", "user", "legacy", "migration"} {
		t.Run(source, func(t *testing.T) {
			before := map[string]stateledger.Answer{"enabled": {Value: false, Source: source}}
			resolved, err := ResolveSettingsAnswers(tpl, before, []string{"features=a"})
			if source != "default" {
				if !errors.Is(err, ErrSettingsInput) {
					t.Fatalf("explicit origin lost: %v", err)
				}
				return
			}
			if err != nil || resolved.Values["enabled"] != true {
				t.Fatalf("default origin did not imply: %v %+v", err, resolved)
			}
			after, err := settingsAnswerAfterimages(tpl, before, resolved.Values, []string{"features=a"})
			if err != nil || after["enabled"].Source != "default" || after["features"].Source != "user" {
				t.Fatalf("implied origin: %v %+v", err, after)
			}
		})
	}
}

func TestNativeAnswersExplicitSameValueAndUntouchedOrigins(t *testing.T) {
	tpl := answerPolicyTemplate(t)
	before := map[string]stateledger.Answer{"label": {Value: "alpha", Source: "default"}, "parent": {Value: "off", Source: "migration"}, "child": {Value: "prior", Source: "legacy"}, "features": {Value: []any{}, Source: "user"}}
	resolved, err := ResolveSettingsAnswers(tpl, before, []string{"label=alpha"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := settingsAnswerAfterimages(tpl, before, resolved.Values, []string{"label=alpha"})
	if err != nil || after["label"].Source != "user" || after["parent"].Source != "migration" || after["child"].Source != "legacy" || after["child"].Value != "prior" || after["features"].Source != "user" {
		t.Fatalf("answer origins: %v %+v", err, after)
	}
	if before["label"].Source != "default" || settingsAnswersEqual(before, after) {
		t.Fatal("provenance-only change lost or input mutated")
	}
	again, err := settingsAnswerAfterimages(tpl, after, resolved.Values, []string{"label=alpha"})
	if err != nil || !settingsAnswersEqual(after, again) {
		t.Fatalf("same user answer not stable: %v", err)
	}
}

func TestNativeAnswersDefaultOriginRecomputesAndInactiveSnapshotsStay(t *testing.T) {
	tpl := answerPolicyTemplate(t)
	before := map[string]stateledger.Answer{"enabled": {Value: true, Source: "default"}, "features": {Value: []string{"a"}, Source: "user"}, "child": {Value: "prior", Source: "user"}}
	resolved, err := ResolveSettingsAnswers(tpl, before, []string{"features="})
	if err != nil || resolved.Values["enabled"] != false || resolved.Values["child"] != "prior" || resolved.ActiveValues["child"] != "" {
		t.Fatalf("default or inactive snapshot: %v %+v", err, resolved)
	}
	if !reflect.DeepEqual(before["features"].Value, []string{"a"}) {
		t.Fatal("mutated input")
	}
	for _, pairs := range [][]string{{"child=changed"}, {"parent=off", "child=changed"}, {"parent=on", "parent=off"}} {
		if _, err := ResolveSettingsAnswers(tpl, before, pairs); !errors.Is(err, ErrSettingsInput) {
			t.Fatalf("inactive/duplicate input accepted %v: %v", pairs, err)
		}
	}
	resolved, err = ResolveSettingsAnswers(tpl, before, []string{"child=changed", "parent=on"})
	if err != nil || resolved.ActiveValues["child"] != "changed" {
		t.Fatalf("parent-driven activation rejected: %v", err)
	}
	if !SettingsGroupActive(tpl, settings.Values{"parent": "on"}, "child") || SettingsGroupActive(tpl, settings.Values{"parent": "off"}, "child") {
		t.Fatal("ancestry")
	}
}

func TestNativeAnswersOriginalAncestryCannotBeOpenedByDefaultRecomputation(t *testing.T) {
	tpl := answerPolicyTemplate(t)
	tpl.Settings[3].Default = "on"
	before := map[string]stateledger.Answer{"parent": {Value: "off", Source: "default"}}
	if _, err := ResolveSettingsAnswers(tpl, before, []string{"child=changed"}); !errors.Is(err, ErrSettingsInput) {
		t.Fatalf("default recomputation exposed inactive descendant: %v", err)
	}
	resolved, err := ResolveSettingsAnswers(tpl, before, []string{"child=changed", "parent=on"})
	if err != nil || resolved.ActiveValues["child"] != "changed" {
		t.Fatalf("explicit parent activation: %v %+v", err, resolved)
	}
}

func TestNativeAnswersUntouchedInactiveDefaultSnapshots(t *testing.T) {
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: inactive-default, version: 1.0.0, description: fixture}
engine: {type: gotemplate, root: files}
settings:
 - {group: label, title: Label, type: string, default: alpha}
 - group: parent
   title: Parent
   type: select
   default: off
   options:
    - {id: off, title: Off}
    - id: on
      title: On
      requires: ["child=true"]
      settings:
       - {group: child, title: Child, type: toggle, default: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	initial := map[string]stateledger.Answer{"parent": {Value: "on", Source: "user"}, "child": {Value: true, Source: "default"}, "label": {Value: "alpha", Source: "default"}}
	active, err := ResolveSettingsAnswers(tpl, initial, nil)
	if err != nil || active.Values["child"] != true || active.ActiveValues["child"] != true {
		t.Fatalf("genuine implied default snapshot: %v %+v", err, active)
	}
	for _, tc := range []struct {
		name, parent string
		pairs        []string
	}{
		{"parent-deactivation", "on", []string{"parent=off"}},
		{"already-inactive-unrelated-edit", "off", []string{"label=beta"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := map[string]stateledger.Answer{"parent": {Value: tc.parent, Source: "user"}, "child": initial["child"], "label": initial["label"]}
			resolved, err := ResolveSettingsAnswers(tpl, before, tc.pairs)
			if err != nil {
				t.Fatal(err)
			}
			after, err := settingsAnswerAfterimages(tpl, before, resolved.Values, tc.pairs)
			if err != nil {
				t.Fatal(err)
			}
			if after["child"] != before["child"] || resolved.Values["child"] != true || resolved.ActiveValues["child"] != false {
				t.Fatalf("inactive snapshot lost or rendered: before=%+v after=%+v snapshot=%v render=%v", before["child"], after["child"], resolved.Values["child"], resolved.ActiveValues["child"])
			}
			// Publication's rendering resolver must see the same stored snapshot while
			// retaining the inactive rendering floor.
			rendered, err := settings.Resolve(tpl, resolved.Values)
			if err != nil || rendered.Values["child"] != true || rendered.ActiveValues["child"] != false {
				t.Fatalf("render reconstruction diverged: %v %+v", err, rendered)
			}
			// Defend the metadata seam even when given default-recomputed values.
			recomputed := resolved.Values.Clone()
			recomputed["child"] = false
			guarded, err := settingsAnswerAfterimages(tpl, before, recomputed, tc.pairs)
			if err != nil || guarded["child"] != before["child"] {
				t.Fatalf("metadata overwrote inactive default: %v %+v", err, guarded)
			}
		})
	}
}

func TestDeprecatedRecordedDefaultOriginsAndInactiveSnapshots(t *testing.T) {
	tpl := answerPolicyTemplate(t)
	tpl.Settings[0].Deprecated = true
	tpl.Settings[0].Default = nil
	tpl.Settings[3].Options[1].Settings[0].Deprecated = true
	tpl.Settings[3].Options[1].Settings[0].Default = nil
	for _, source := range []string{"default", "user", "legacy", "migration"} {
		before := map[string]stateledger.Answer{"label": {Value: "alpha", Source: source}, "parent": {Value: "off", Source: "default"}, "child": {Value: "prior", Source: source}}
		resolved, err := ResolveSettingsAnswers(tpl, before, []string{"enabled=true"})
		if err != nil {
			t.Fatal(err)
		}
		after, err := settingsAnswerAfterimages(tpl, before, resolved.Values, []string{"enabled=true"})
		if err != nil {
			t.Fatal(err)
		}
		if after["label"] != before["label"] || after["child"] != before["child"] || resolved.ActiveValues["child"] != "" {
			t.Fatal("retained origin/value/ancestry lost", after)
		}
		same, err := ResolveSettingsAnswers(tpl, before, []string{"label=alpha"})
		if err != nil {
			t.Fatal(err)
		}
		intent, err := settingsAnswerAfterimages(tpl, before, same.Values, []string{"label=alpha"})
		if err != nil || intent["label"].Source != "user" {
			t.Fatal("same-value intent lost", err)
		}
		for _, pairs := range [][]string{{"label=changed"}, {"child=prior"}} {
			if _, err := ResolveSettingsAnswers(tpl, before, pairs); !errors.Is(err, ErrSettingsInput) {
				t.Fatal("retired change/hidden override accepted", err)
			}
		}
	}
	missing, err := ResolveSettingsAnswers(tpl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := missing.Values["label"]; exists {
		t.Fatal("prior default synthesized retired record")
	}
}

func TestDeprecatedDefaultOriginYAMLMultiselectRetention(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{{Group: "many", Type: manifest.TypeMultiselect, Default: []any{}, Options: []manifest.Option{{ID: "old", Deprecated: true}, {ID: "new"}}}}}
	before := map[string]stateledger.Answer{"many": {Value: []any{"old"}, Source: "default"}}
	resolved, err := ResolveSettingsAnswers(tpl, before, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolved.Values["many"], []string{"old"}) {
		t.Fatalf("YAML default-origin retired members lost: %v", resolved.Values["many"])
	}
	after, err := settingsAnswerAfterimages(tpl, before, resolved.Values, nil)
	if err != nil || after["many"].Source != "default" {
		t.Fatal("retained origin lost", err)
	}
	changed, err := ResolveSettingsAnswers(tpl, before, []string{"many=old,new"})
	if err != nil || !reflect.DeepEqual(changed.Values["many"], []string{"old", "new"}) {
		t.Fatal("mixed supported/retained members", err)
	}
	removed, err := ResolveSettingsAnswers(tpl, before, []string{"many=new"})
	if err != nil {
		t.Fatal(err)
	}
	records, err := settingsAnswerAfterimages(tpl, before, removed.Values, []string{"many=new"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSettingsAnswers(tpl, records, []string{"many=old"}); !errors.Is(err, ErrSettingsInput) {
		t.Fatal("removed YAML member reintroduced", err)
	}
}
