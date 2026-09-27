package settings

import "testing"

func TestRenderContext_SettingsAndHelpers(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{
		"database": "postgres",
		"brokers":  []string{"kafka"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ctx := RenderContext(tpl, res)
	sv, ok := ctx["Settings"].(View)
	if !ok {
		t.Fatalf(".Settings не View: %T", ctx["Settings"])
	}

	// Map-style access (.Settings.<group> in a template).
	if sv["database"] != "postgres" {
		t.Errorf("Settings.database = %v", sv["database"])
	}

	// Is: select/string/toggle equality.
	if !sv.Is("database", "postgres") {
		t.Errorf("Is(database, postgres) должно быть true")
	}
	if sv.Is("database", "mysql") {
		t.Errorf("Is(database, mysql) должно быть false")
	}
	if !sv.Is("metrics", "false") {
		t.Errorf("Is(metrics, false) должно быть true (toggle=false)")
	}
	// Is on a multiselect is meaningless -> false.
	if sv.Is("brokers", "kafka") {
		t.Errorf("Is на multiselect должно быть false, используйте Has")
	}

	// Has: multiselect contains.
	if !sv.Has("brokers", "kafka") {
		t.Errorf("Has(brokers, kafka) должно быть true")
	}
	if sv.Has("brokers", "nats") {
		t.Errorf("Has(brokers, nats) должно быть false")
	}
	// Has on a non-multiselect -> false.
	if sv.Has("database", "postgres") {
		t.Errorf("Has на select должно быть false, используйте Is")
	}
}
