package inittemplate

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// comboTemplate — манифест с select (2 опции), multiselect (2 опции), toggle и
// вложенным toggle под select-опцией; опция requires другую группу
// (транзитивность).
func comboTemplate() *manifest.Template {
	return &manifest.Template{
		Settings: []manifest.SettingGroup{
			{
				Group: "database", Type: manifest.TypeSelect, Default: "none",
				Options: []manifest.Option{
					{ID: "none"},
					{ID: "postgres", Settings: []manifest.SettingGroup{
						{Group: "migrations", Type: manifest.TypeToggle, Default: false},
					}},
				},
			},
			{
				Group: "brokers", Type: manifest.TypeMultiselect,
				Options: []manifest.Option{
					{ID: "kafka"},
					{ID: "rabbitmq"},
					{ID: "nats", Status: manifest.StatusPlanned},
				},
			},
			{Group: "cache", Type: manifest.TypeToggle, Default: false},
			{
				Group: "auth", Type: manifest.TypeMultiselect,
				Options: []manifest.Option{
					// requires транзитивно тянет database=postgres.
					{ID: "sso", Requires: []string{"database=postgres"}},
				},
			},
		},
	}
}

func TestCombos_Composition(t *testing.T) {
	combos := Combos(comboTemplate())

	got := make(map[string]settings.Values, len(combos))
	for _, c := range combos {
		if _, dup := got[c.Name]; dup {
			t.Fatalf("дублирующееся имя комбо %q", c.Name)
		}
		got[c.Name] = c.Explicit
	}

	want := []string{
		"defaults",
		"database=none", "database=postgres",
		"brokers=kafka", "brokers=rabbitmq",
		"auth=sso",
		"all-on", "max",
	}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("ожидалась комбо %q, её нет; есть: %v", name, keys(got))
		}
	}

	// planned-опция nats не должна порождать комбо.
	if _, ok := got["brokers=nats"]; ok {
		t.Errorf("planned-опция nats не должна давать комбо")
	}

	// all-on выставляет ВСЕ toggle (включая вложенный migrations) в true.
	allOn := got["all-on"]
	if allOn["cache"] != true || allOn["migrations"] != true {
		t.Errorf("all-on должен включать все toggle: %#v", allOn)
	}

	// max: toggle=true + multiselect выбраны целиком (без planned) + select на
	// последней опции.
	maxVals := got["max"]
	if maxVals["database"] != "postgres" {
		t.Errorf("max.database ожидался postgres (последняя опция), получено %v", maxVals["database"])
	}
	if br, _ := maxVals["brokers"].([]string); len(br) != 2 {
		t.Errorf("max.brokers ожидались обе не-planned опции, получено %v", maxVals["brokers"])
	}
}

func TestCombos_RequiresTransitivity(t *testing.T) {
	combos := Combos(comboTemplate())
	var authCombo *Combo
	for i := range combos {
		if combos[i].Name == "auth=sso" {
			authCombo = &combos[i]
		}
	}
	if authCombo == nil {
		t.Fatal("нет комбо auth=sso")
	}

	// Комбо задаёт только auth=[sso]; Resolve обязан транзитивно дотянуть
	// database=postgres через requires опции sso.
	resolved, err := settings.Resolve(comboTemplate(), authCombo.Explicit)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Values["database"] != "postgres" {
		t.Errorf("requires не дотянул database=postgres: %v", resolved.Values["database"])
	}
	if len(resolved.Report.Implied) == 0 {
		t.Errorf("ожидалось довключение в отчёте резолвера")
	}
}

func TestFilterCombos(t *testing.T) {
	combos := Combos(comboTemplate())
	filtered, known := FilterCombos(combos, "database=postgres")
	if len(filtered) != 1 || filtered[0].Name != "database=postgres" {
		t.Errorf("фильтр по имени: получено %v", names(filtered))
	}
	if len(known) == 0 {
		t.Errorf("known-список пуст")
	}

	all, _ := FilterCombos(combos, "")
	if len(all) != len(combos) {
		t.Errorf("пустой фильтр должен вернуть все: %d != %d", len(all), len(combos))
	}
}

func keys(m map[string]settings.Values) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func names(combos []Combo) []string {
	out := make([]string, 0, len(combos))
	for _, c := range combos {
		out = append(out, c.Name)
	}
	return out
}
