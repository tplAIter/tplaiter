package updateplan

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestNativeSettingsTypedOverridesAndBounds(t *testing.T) {
	tpl, err := manifest.ParseTemplate([]byte(`apiVersion: tplater.dev/v1alpha1
kind: Template
metadata: {name: settings, version: 1.0.0, description: fixture}
engine: {type: gotemplate, root: files}
settings:
 - {group: label, title: Label, type: string, default: default}
 - {group: count, title: Count, type: int, default: 1}
 - {group: enabled, title: Enabled, type: toggle, default: false}
 - group: features
   title: Features
   type: multiselect
   default: []
   options:
    - {id: a, title: A}
    - {id: b, title: B, requires: ["enabled=true"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	old := settings.Values{"label": "local", "count": 1, "enabled": false, "features": []string{}}
	resolved, err := ResolveSettingsPairs(tpl, old, []string{"count=7", "features=a,b"})
	if err != nil || resolved.Values["count"] != 7 || resolved.Values["label"] != "local" || resolved.Values["enabled"] != true || !reflect.DeepEqual(resolved.Values["features"], []string{"a", "b"}) {
		t.Fatalf("typed settings: %v %+v", err, resolved)
	}
	if old["count"] != 1 || old["enabled"] != false {
		t.Fatal("settings mutated caller values")
	}
	for _, pairs := range [][]string{{"count=x"}, {"features=b", "enabled=false"}, {"count=1", "count=2"}, {"missing=x"}} {
		if _, err := ResolveSettingsPairs(tpl, old, pairs); !errors.Is(err, ErrSettingsInput) {
			t.Fatalf("invalid %v: %v", pairs, err)
		}
	}
	for _, in := range []Input{
		{SourceInput: []byte("a"), TargetInput: []byte("b"), SettingsPairs: []string{"count=1"}},
		{SettingsPairs: []string{strings.Repeat("x", 4097)}},
		{SettingsPairs: make([]string, 129)},
	} {
		if _, err := cloneSettingsInput(in); !errors.Is(err, ErrSettingsInput) {
			t.Fatalf("unbounded override: %v", err)
		}
	}
}
