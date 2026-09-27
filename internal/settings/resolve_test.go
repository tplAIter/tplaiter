package settings

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResolve_TransitiveChain(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{"auth": []string{"sso_provider"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Values["database"] != "postgres" {
		t.Errorf("database = %v, ожидалось postgres (довключено через sso_provider)", res.Values["database"])
	}
	want := []ImpliedValue{{Group: "database", Value: "postgres", RequiredBy: "sso_provider"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, ожидалось %#v", res.Report.Implied, want)
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("предупреждений быть не должно, получено: %v", res.Report.Warnings)
	}
}

func TestResolve_MultiselectImplication(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{"auth": []string{"audit"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	brokers, _ := res.Values["brokers"].([]string)
	if !contains(brokers, "kafka") {
		t.Errorf("brokers = %v, ожидалось содержит kafka (довключено audit)", brokers)
	}
	want := []ImpliedValue{{Group: "brokers", Value: "kafka", RequiredBy: "audit"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, ожидалось %#v", res.Report.Implied, want)
	}
	// kafka is now selected -> kafka_ssl is active and not reset.
	if res.ActiveValues["kafka_ssl"] != false {
		t.Errorf("kafka_ssl = %v", res.ActiveValues["kafka_ssl"])
	}
}

func TestResolve_ToggleImplication(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{"extras": []string{"dashboards"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Values["metrics"] != true {
		t.Errorf("metrics = %v, ожидалось true (довключено dashboards)", res.Values["metrics"])
	}
	want := []ImpliedValue{{Group: "metrics", Value: "true", RequiredBy: "dashboards"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, ожидалось %#v", res.Report.Implied, want)
	}
}

func TestResolve_ConflictExplicitVsRequires(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	_, err := Resolve(tpl, Values{
		"database": "mysql",
		"auth":     []string{"sso_provider"},
	})
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("ожидался *ConflictError, получено %T (%v)", err, err)
	}
	msg := ce.Error()
	if !strings.Contains(msg, "sso_provider требует database=postgres, но задано database=mysql") {
		t.Errorf("сообщение конфликта не содержит ожидаемую цепочку: %q", msg)
	}
}

func TestResolve_RequiresCycle(t *testing.T) {
	tpl := loadFixture(t, "cycle.yaml")
	_, err := Resolve(tpl, nil)
	var cyc *CycleError
	if !errors.As(err, &cyc) {
		t.Fatalf("ожидался *CycleError, получено %T (%v)", err, err)
	}
	if len(cyc.Chain) < 2 {
		t.Errorf("цепочка цикла подозрительно коротка: %v", cyc.Chain)
	}
}

func TestResolve_ConstraintViolation(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	// idempotency=true but database=none violates the constraint.
	_, err := Resolve(tpl, Values{"idempotency": true})
	var cerr *ConstraintError
	if !errors.As(err, &cerr) {
		t.Fatalf("ожидался *ConstraintError, получено %T (%v)", err, err)
	}
	if cerr.Message != "Идемпотентность требует PostgreSQL" {
		t.Errorf("сообщение constraint = %q", cerr.Message)
	}
}

func TestResolve_InactiveNestedResetWithWarning(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	// kafka_ssl=true but kafka is not selected in brokers.
	res, err := Resolve(tpl, Values{"kafka_ssl": true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Values["kafka_ssl"] != true {
		t.Errorf("полный снимок должен хранить kafka_ssl=true, получено %v", res.Values["kafka_ssl"])
	}
	if res.ActiveValues["kafka_ssl"] != false {
		t.Errorf("ActiveValues.kafka_ssl должно быть сброшено в false, получено %v", res.ActiveValues["kafka_ssl"])
	}
	found := false
	for _, w := range res.Report.Warnings {
		if strings.Contains(w, "kafka_ssl") && strings.Contains(w, "неактивна") {
			found = true
		}
	}
	if !found {
		t.Errorf("ожидалось предупреждение про неактивную kafka_ssl, получено: %v", res.Report.Warnings)
	}
}

func TestResolve_InactiveNonDefault_NoSpuriousWarning(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	// Plain postgres: pg_shards (default 4) is inactive with pg_pool=small, but
	// the value equals the default -> there must be no warning.
	res, err := Resolve(tpl, Values{"database": "postgres"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.ActiveValues["pg_shards"] != 0 {
		t.Errorf("pg_shards в Active = %v, ожидалось 0 (сброс)", res.ActiveValues["pg_shards"])
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("ложные предупреждения: %v", res.Report.Warnings)
	}
}

func TestResolve_DefaultsOnly_NoImpliedNoWarnings(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Report.Implied) != 0 {
		t.Errorf("Implied должно быть пустым: %#v", res.Report.Implied)
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("Warnings должно быть пустым: %v", res.Report.Warnings)
	}
}

func TestResolve_UnknownExplicitGroupWarns(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{"bogus": "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	found := false
	for _, w := range res.Report.Warnings {
		if strings.Contains(w, "bogus") {
			found = true
		}
	}
	if !found {
		t.Errorf("ожидалось предупреждение про неизвестную группу bogus: %v", res.Report.Warnings)
	}
}
