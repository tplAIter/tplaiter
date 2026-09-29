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
		t.Fatalf(".Settings is not a View: %T", ctx["Settings"])
	}

	// Map-style access (.Settings.<group> in a template).
	if sv["database"] != "postgres" {
		t.Errorf("Settings.database = %v", sv["database"])
	}

	// Is: select/string/toggle equality.
	if !sv.Is("database", "postgres") {
		t.Errorf("Is(database, postgres) must be true")
	}
	if sv.Is("database", "mysql") {
		t.Errorf("Is(database, mysql) must be false")
	}
	if !sv.Is("metrics", "false") {
		t.Errorf("Is(metrics, false) must be true (toggle=false)")
	}
	// Is on a multiselect is meaningless -> false.
	if sv.Is("brokers", "kafka") {
		t.Errorf("Is on a multiselect must be false; use Has")
	}

	// Has: multiselect contains.
	if !sv.Has("brokers", "kafka") {
		t.Errorf("Has(brokers, kafka) must be true")
	}
	if sv.Has("brokers", "nats") {
		t.Errorf("Has(brokers, nats) must be false")
	}
	// Has on a non-multiselect -> false.
	if sv.Has("database", "postgres") {
		t.Errorf("Has on a select must be false; use Is")
	}
}
