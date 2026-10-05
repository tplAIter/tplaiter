package settingscmd_test

import (
	"io"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/settingscmd"
	"github.com/tplAIter/tplaiter/internal/survey"
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
	pairs, err := settingscmd.Reanswer(&settingscmd.NativeView{Template: tpl, Values: settings.Values{"label": "local", "database": "none", "auth": "none"}}, "auth", settingscmd.Deps{Interactive: true, Prompter: prompter, Out: io.Discard, Err: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pairs, []string{"auth=oauth"}) || !reflect.DeepEqual(prompter.AskCalls, [][]string{{"auth"}}) {
		t.Fatalf("reanswer: %v %v", pairs, prompter.AskCalls)
	}
}
