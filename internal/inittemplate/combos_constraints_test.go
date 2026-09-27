package inittemplate

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// TestCombosSatisfyConstraints — all-on с toggle, требующим select-значение
// через constraints, довключает это значение (находка  на go-template).
func TestCombosSatisfyConstraints(t *testing.T) {
	t.Parallel()
	tpl := &manifest.Template{
		Settings: []manifest.SettingGroup{
			{Group: "database", Type: manifest.TypeSelect, Default: "none", Options: []manifest.Option{
				{ID: "none"}, {ID: "postgres"},
			}},
			{Group: "idempotency", Type: manifest.TypeToggle, Default: false},
		},
		Constraints: []manifest.Constraint{
			{If: "idempotency=true", Require: "database=postgres", Message: "нужен postgres"},
		},
	}
	for _, c := range Combos(tpl) {
		if c.Name == "all-on" {
			if got, ok := c.Explicit["database"].(string); !ok || got != "postgres" {
				t.Fatalf("all-on не довключил database=postgres: %#v", c.Explicit)
			}
			return
		}
	}
	t.Fatal("комбо all-on не найдено")
}
