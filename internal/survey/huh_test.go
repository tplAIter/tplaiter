package survey

import (
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestBuildForm_ConstructsFieldPerGroup(t *testing.T) {
	tpl := testTemplate()
	form, binds, err := buildForm(tpl.Settings, settings.DefaultValues(tpl))
	if err != nil {
		t.Fatalf("buildForm: %v", err)
	}
	if form == nil {
		t.Fatalf("form must not be nil")
	}
	// All 8 groups in the tree (including nested groups) received a binding/field.
	want := []string{
		"database", "idempotency", "brokers",
		"kafka_ssl", "kafka_topics", "auth", "svc_name", "replicas",
	}
	if len(binds) != len(want) {
		t.Fatalf("bindings %d, want %d (%v)", len(binds), len(want), want)
	}
	for _, id := range want {
		if _, ok := binds[id]; !ok {
			t.Errorf("no binding for group %q", id)
		}
	}
}

func TestBuildForm_BadPatternPropagatesError(t *testing.T) {
	tpl := &manifest.Template{
		Settings: []manifest.SettingGroup{
			{Group: "x", Type: manifest.TypeString, Pattern: "([a-z"},
		},
	}
	if _, _, err := buildForm(tpl.Settings, settings.DefaultValues(tpl)); err == nil {
		t.Fatalf("expected a pattern compile error")
	}
}

func TestSelectableOptions_FiltersPlanned(t *testing.T) {
	tpl := testTemplate()
	var database *manifest.SettingGroup
	for i := range tpl.Settings {
		if tpl.Settings[i].Group == "database" {
			database = &tpl.Settings[i]
		}
	}
	opts, planned := selectableOptions(database, nil)
	if len(opts) != 2 {
		t.Fatalf("selectable options %d, want 2 (none, postgres)", len(opts))
	}
	if len(planned) != 1 || planned[0] != "MySQL" {
		t.Fatalf("planned = %v, want [MySQL]", planned)
	}
	desc := fieldDescription(database, planned)
	if !strings.Contains(desc, "planned") || !strings.Contains(desc, "MySQL") {
		t.Fatalf("description does not reflect the planned option: %q", desc)
	}
}

func TestSelectableOptions_MultiselectPreselect(t *testing.T) {
	g := &manifest.SettingGroup{
		Group: "brokers", Type: manifest.TypeMultiselect,
		Options: []manifest.Option{{ID: "kafka"}, {ID: "rabbitmq"}},
	}
	opts, _ := selectableOptions(g, []string{"kafka"})
	if len(opts) != 2 {
		t.Fatalf("options %d, want 2", len(opts))
	}
}

func TestBinding_ValueRoundTrip(t *testing.T) {
	cases := []struct {
		g    manifest.SettingGroup
		cur  any
		want any
	}{
		{manifest.SettingGroup{Group: "s", Type: manifest.TypeSelect}, "postgres", "postgres"},
		{manifest.SettingGroup{Group: "m", Type: manifest.TypeMultiselect}, []string{"a"}, []string{"a"}},
		{manifest.SettingGroup{Group: "t", Type: manifest.TypeToggle}, true, true},
		{manifest.SettingGroup{Group: "i", Type: manifest.TypeInt}, 42, 42},
		{manifest.SettingGroup{Group: "str", Type: manifest.TypeString}, "hi", "hi"},
	}
	for _, c := range cases {
		g := c.g
		bd := newBinding(&g, c.cur)
		got := bd.value()
		if !equalAny(got, c.want) {
			t.Errorf("type %s: value() = %v, want %v", g.Type, got, c.want)
		}
	}
}

func TestValidators(t *testing.T) {
	if err := intValidator("12"); err != nil {
		t.Errorf("intValidator(12): %v", err)
	}
	if err := intValidator("x"); err == nil {
		t.Errorf("intValidator(x) must fail")
	}
	v, err := patternValidator("^[a-z]+$")
	if err != nil {
		t.Fatalf("patternValidator: %v", err)
	}
	if err := v("abc"); err != nil {
		t.Errorf("pattern abc: %v", err)
	}
	if err := v("A1"); err == nil {
		t.Errorf("pattern A1 must fail")
	}
}

func equalAny(a, b any) bool {
	if al, ok := a.([]string); ok {
		bl, ok := b.([]string)
		if !ok || len(al) != len(bl) {
			return false
		}
		for i := range al {
			if al[i] != bl[i] {
				return false
			}
		}
		return true
	}
	return a == b
}
