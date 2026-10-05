package settings

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

func TestResolve_TransitiveChain(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{"auth": []string{"sso_provider"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Values["database"] != "postgres" {
		t.Errorf("database = %v, expected postgres (auto-enabled via sso_provider)", res.Values["database"])
	}
	want := []ImpliedValue{{Group: "database", Value: "postgres", RequiredBy: "sso_provider"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, expected %#v", res.Report.Implied, want)
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("should not have warnings, got: %v", res.Report.Warnings)
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
		t.Errorf("brokers = %v, expected contains kafka (auto-enabled by audit)", brokers)
	}
	want := []ImpliedValue{{Group: "brokers", Value: "kafka", RequiredBy: "audit"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, expected %#v", res.Report.Implied, want)
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
		t.Errorf("metrics = %v, expected true (auto-enabled by dashboards)", res.Values["metrics"])
	}
	want := []ImpliedValue{{Group: "metrics", Value: "true", RequiredBy: "dashboards"}}
	if !reflect.DeepEqual(res.Report.Implied, want) {
		t.Errorf("Implied = %#v, expected %#v", res.Report.Implied, want)
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
		t.Fatalf("expected *ConflictError, got %T (%v)", err, err)
	}
	msg := ce.Error()
	if !strings.Contains(msg, "sso_provider requires database=postgres, but database=mysql is set") {
		t.Errorf("conflict message does not contain expected chain: %q", msg)
	}
}

func TestResolve_RequiresCycle(t *testing.T) {
	tpl := loadFixture(t, "cycle.yaml")
	_, err := Resolve(tpl, nil)
	var cyc *CycleError
	if !errors.As(err, &cyc) {
		t.Fatalf("expected *CycleError, got %T (%v)", err, err)
	}
	if len(cyc.Chain) < 2 {
		t.Errorf("cycle chain suspiciously short: %v", cyc.Chain)
	}
}

func TestResolve_ConstraintViolation(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	// idempotency=true but database=none violates the constraint.
	_, err := Resolve(tpl, Values{"idempotency": true})
	var cerr *ConstraintError
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *ConstraintError, got %T (%v)", err, err)
	}
	if cerr.Message != "Idempotency requires PostgreSQL" {
		t.Errorf("constraint message = %q", cerr.Message)
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
		t.Errorf("full snapshot should store kafka_ssl=true, got %v", res.Values["kafka_ssl"])
	}
	if res.ActiveValues["kafka_ssl"] != false {
		t.Errorf("ActiveValues.kafka_ssl should be reset to false, got %v", res.ActiveValues["kafka_ssl"])
	}
	found := false
	for _, w := range res.Report.Warnings {
		if strings.Contains(w, "kafka_ssl") && strings.Contains(w, "inactive") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about inactive kafka_ssl, got: %v", res.Report.Warnings)
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
		t.Errorf("pg_shards in Active = %v, expected 0 (reset)", res.ActiveValues["pg_shards"])
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("spurious warnings: %v", res.Report.Warnings)
	}
}

func TestResolve_DefaultsOnly_NoImpliedNoWarnings(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Report.Implied) != 0 {
		t.Errorf("Implied should be empty: %#v", res.Report.Implied)
	}
	if len(res.Report.Warnings) != 0 {
		t.Errorf("Warnings should be empty: %v", res.Report.Warnings)
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
		t.Errorf("expected warning about unknown group bogus: %v", res.Report.Warnings)
	}
}

func deprecatedResolverTemplate() *manifest.Template {
	return &manifest.Template{Settings: []manifest.SettingGroup{
		{Group: "retired", Type: manifest.TypeToggle, Deprecated: true},
		{Group: "choice", Type: manifest.TypeSelect, Default: "new", Options: []manifest.Option{{ID: "old", Deprecated: true}, {ID: "new"}}},
		{Group: "multi", Type: manifest.TypeMultiselect, Options: []manifest.Option{{ID: "old", Deprecated: true}, {ID: "new"}}},
		{Group: "trigger", Type: manifest.TypeSelect, Options: []manifest.Option{{ID: "on", Requires: []string{"retired=false"}}}},
	}}
}

func TestDeprecatedFreshAndRecordedRequires(t *testing.T) {
	tpl := deprecatedResolverTemplate()
	for _, v := range []Values{{"choice": "old"}, {"multi": []string{"old"}}, {"retired": false}, {"trigger": "on"}} {
		_, err := Resolve(tpl, v)
		var retired *DeprecatedAnswerError
		if !errors.As(err, &retired) {
			t.Fatalf("fresh retired input admitted: %v", err)
		}
	}
	prior := Values{"retired": false, "choice": "old", "multi": []string{"old"}}
	candidate := prior.Clone()
	candidate["trigger"] = "on"
	candidate["multi"] = []string{"old", "new"}
	got, err := ResolveRecorded(tpl, prior, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Report.Warnings) != 3 {
		t.Fatalf("refs %v", got.Report.Warnings)
	}
	candidate["choice"] = "new"
	candidate["multi"] = []string{"new"}
	if _, err := ResolveRecorded(tpl, prior, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveRecorded(tpl, Values{"choice": "new"}, Values{"choice": "old"}); err == nil {
		t.Fatal("removed retired member reintroduced")
	}
	if _, err := ResolveRecorded(tpl, prior, Values{"retired": true}); err == nil {
		t.Fatal("retired scalar changed")
	}
	if _, err := ResolveRecorded(tpl, Values{"retired": "false"}, Values{"retired": "false"}); err == nil {
		t.Fatal("retired record wrong type admitted")
	}
	fresh, err := Resolve(tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Values["retired"]; ok || fresh.ActiveValues["retired"] != false {
		t.Fatal("fresh retired record synthesized or render zero absent")
	}
}

func TestNoDeprecationRecordedCalculationIdentical(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	v := Values{"auth": []string{"audit"}}
	fresh, err := Resolve(tpl, v)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := ResolveRecorded(tpl, v, v)
	if err != nil || !reflect.DeepEqual(fresh, recorded) {
		t.Fatal("ordinary recorded calculation changed", err)
	}
}

// Each compatibility route reconstructs the same raw Values map from an
// authenticated marker and delegates its retained calculation to ResolveRecorded.
// This covers that shared seam; it does not claim installed Gen/build execution.
func TestRecordedDeprecatedMultiselectYAMLCompatibility(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{
		{Group: "retired", Type: manifest.TypeMultiselect, Deprecated: true, Options: []manifest.Option{{ID: "old"}, {ID: "new"}}},
	}}
	for _, caller := range []string{"cmd/gen_native", "gen/native_plan", "operationtrust/project_build"} {
		t.Run(caller, func(t *testing.T) {
			var marker stateledger.ProjectV2
			if err := yaml.Unmarshal([]byte("answers:\n  retired:\n    value: [old]\n    source: user\n"), &marker); err != nil {
				t.Fatal(err)
			}
			values := Values{}
			for key, answer := range marker.Answers {
				values[key] = answer.Value
			}
			carrier, ok := values["retired"].([]any)
			if !ok {
				t.Fatalf("actual YAML carrier = %T", values["retired"])
			}
			got, err := ResolveRecorded(tpl, values, values)
			if err != nil {
				t.Fatal(err)
			}
			control, err := ResolveRecorded(tpl, Values{"retired": []string{"old"}}, Values{"retired": []string{"old"}})
			if err != nil || !reflect.DeepEqual(got, control) {
				t.Fatalf("carrier changed retained content: %v", err)
			}
			got.Values["retired"].([]string)[0] = "new"
			if carrier[0] != "old" || marker.Answers["retired"].Source != "user" {
				t.Fatal("calculation mutated authenticated answer")
			}
			if _, err := ResolveRecorded(tpl, nil, values); err == nil {
				t.Fatal("new retired record admitted")
			}
			if _, err := Resolve(tpl, values); err == nil {
				t.Fatal("fresh retired YAML input admitted")
			}
		})
	}
}

func TestRecordedYAMLMultiselectStrictMembers(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{
		{Group: "retired", Type: manifest.TypeMultiselect, Deprecated: true, Options: []manifest.Option{{ID: "old"}}},
	}}
	for _, raw := range []string{"[old, 1]", "[old, true]", "[old, null]", "[old, [old]]", "[old, {key: old}]"} {
		t.Run(raw, func(t *testing.T) {
			var marker stateledger.ProjectV2
			if err := yaml.Unmarshal([]byte("answers:\n  retired:\n    value: "+raw+"\n    source: user\n"), &marker); err != nil {
				t.Fatal(err)
			}
			values := Values{"retired": marker.Answers["retired"].Value}
			valid := Values{"retired": []string{"old"}}
			for _, input := range [][2]Values{{values, valid}, {valid, values}, {values, values}} {
				got, err := ResolveRecorded(tpl, input[0], input[1])
				if err == nil || !reflect.DeepEqual(got, Resolved{}) {
					t.Fatal("malformed prior/explicit list coerced or partially returned", err)
				}
			}
		})
	}
}
