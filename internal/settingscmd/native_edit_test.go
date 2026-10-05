package settingscmd_test

import (
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/updateplan"
)

func TestNativeReanswerPreservesOtherGroupsAndResolvesRequires(t *testing.T) {
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: reanswer, version: 1.0.0, description: fixture}
engine: {type: gotemplate, root: files}
settings:
  - {group: label, title: Label, type: string, default: keep}
  - group: database
    title: Database
    type: select
    default: none
    options: [{id: none, title: None}, {id: postgres, title: PostgreSQL}]
  - group: auth
    title: Auth
    type: select
    default: none
    options:
      - {id: none, title: None}
      - id: oauth
        title: OAuth
        requires: ["database=postgres"]
`))
	if err != nil {
		t.Fatal(err)
	}
	prompter := &survey.ScriptedPrompter{Answers: []settings.Values{{"auth": "oauth"}}}
	pairs, err := settingscmd.Reanswer(&settingscmd.NativeView{Template: tpl, Values: settings.Values{"label": "local", "database": "none", "auth": "none"}, Answers: map[string]stateledger.Answer{"label": {Value: "local", Source: "user"}, "database": {Value: "none", Source: "default"}, "auth": {Value: "none", Source: "default"}}}, "auth", settingscmd.Deps{Interactive: true, Prompter: prompter, Out: io.Discard, Err: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pairs, []string{"auth=oauth"}) || !reflect.DeepEqual(prompter.AskCalls, [][]string{{"auth"}}) {
		t.Fatalf("reanswer: %v %v", pairs, prompter.AskCalls)
	}
}

func TestNativeReanswerOriginalAncestryAndParentActivation(t *testing.T) {
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: ancestry, version: 1.0.0, description: fixture}
engine: {type: gotemplate, root: files}
settings:
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
	view := &settingscmd.NativeView{Template: tpl, Values: settings.Values{"parent": "off", "child": "prior"}, Answers: map[string]stateledger.Answer{"parent": {Value: "off", Source: "default"}, "child": {Value: "prior", Source: "user"}}}
	d := settingscmd.Deps{Interactive: true, Out: io.Discard, Err: io.Discard}
	p := &survey.ScriptedPrompter{Answers: []settings.Values{{"child": "changed"}}}
	d.Prompter = p
	if _, err := settingscmd.Reanswer(view, "child", d); !errors.Is(err, updateplan.ErrSettingsInput) || len(p.AskCalls) != 0 {
		t.Fatalf("inactive descendant reached prompt: %v %+v", err, p.AskCalls)
	}
	p = &survey.ScriptedPrompter{Answers: []settings.Values{{"parent": "on", "child": "changed"}}}
	d.Prompter = p
	pairs, err := settingscmd.Reanswer(view, "parent", d)
	if err != nil || !reflect.DeepEqual(pairs, []string{"parent=on", "child=changed"}) {
		t.Fatalf("parent activation: %v %v", pairs, err)
	}
	view.Values["parent"] = "on"
	view.Answers["parent"] = stateledger.Answer{Value: "on", Source: "user"}
	p = &survey.ScriptedPrompter{Answers: []settings.Values{{"parent": "off", "child": "ignored"}}}
	d.Prompter = p
	pairs, err = settingscmd.Reanswer(view, "parent", d)
	if err != nil || !reflect.DeepEqual(pairs, []string{"parent=off"}) {
		t.Fatalf("inactive descendant submitted: %v %v", pairs, err)
	}
	if view.Answers["child"].Value != "prior" {
		t.Fatal("reanswer mutated prior snapshot")
	}
}

func TestDeprecatedNativeReanswerRetainedChoicesAndReadonlyGroup(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{{Group: "choice", Type: manifest.TypeSelect, Default: "new", Options: []manifest.Option{{ID: "old", Deprecated: true}, {ID: "new"}}}, {Group: "retired", Type: manifest.TypeToggle, Deprecated: true}}}
	view := &settingscmd.NativeView{Template: tpl, Values: settings.Values{"choice": "old", "retired": false}, Answers: map[string]stateledger.Answer{"choice": {Value: "old", Source: "default"}, "retired": {Value: false, Source: "default"}}}
	for _, choice := range []string{"old", "new"} {
		p := &survey.ScriptedPrompter{Answers: []settings.Values{{"choice": choice}}}
		pairs, err := settingscmd.Reanswer(view, "choice", settingscmd.Deps{Interactive: true, Prompter: p, Out: io.Discard, Err: io.Discard})
		if err != nil || !reflect.DeepEqual(pairs, []string{"choice=" + choice}) {
			t.Fatal("retained/replacement prompt failed", err, pairs)
		}
	}
	p := &survey.ScriptedPrompter{Answers: []settings.Values{{"retired": true}}}
	pairs, err := settingscmd.Reanswer(view, "retired", settingscmd.Deps{Interactive: true, Prompter: p, Out: io.Discard, Err: io.Discard})
	if err != nil || len(pairs) != 0 {
		t.Fatal("readonly group submitted", err, pairs)
	}
}
