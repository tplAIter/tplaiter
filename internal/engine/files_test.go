package engine

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestCompileFileRulesPathsExcludedWhenFalse(t *testing.T) {
	rules := []manifest.FileRule{
		{When: "database=postgres", Paths: []string{"internal/infra/db/**"}},
	}
	gs, err := compileFileRules(rules, settings.Values{"database": "none"})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if !gs.matchAny("internal/infra/db/schema.sql") {
		t.Error("expected paths glob to be excluded (condition false)")
	}
}

func TestCompileFileRulesPathsKeptWhenTrue(t *testing.T) {
	rules := []manifest.FileRule{
		{When: "database=postgres", Paths: []string{"internal/infra/db/**"}},
	}
	gs, err := compileFileRules(rules, settings.Values{"database": "postgres"})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if gs.matchAny("internal/infra/db/schema.sql") {
		t.Error("expected paths glob to stay included (condition true)")
	}
}

// TestCompileFileRulesAnyOfIsOr fixes anyOf semantics: the condition list is
// combined through settings.EvalAny with OR, not AND. The field name suggests
// the opposite, and the  example illustrates composite removal, which needs
// AND (see the behavior description). Composite removal (“neither kafka nor
// rabbit”) is expressed by one `when` with `&&` (settings.Eval), not anyOf.
func TestCompileFileRulesAnyOfIsOr(t *testing.T) {
	rules := []manifest.FileRule{
		{AnyOf: []string{"database=postgres", "brokers=kafka"}, Remove: []string{"legacy/**"}},
	}

	// Only the first atom (database=postgres) is true; OR is still true.
	gs, err := compileFileRules(rules, settings.Values{"database": "postgres", "brokers": []string{}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if !gs.matchAny("legacy/notice.txt") {
		t.Error("anyOf — OR: истинности одного условия достаточно, remove должен сработать")
	}

	// Both atoms are false; OR is false and remove does not apply.
	gs, err = compileFileRules(rules, settings.Values{"database": "none", "brokers": []string{}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if gs.matchAny("legacy/notice.txt") {
		t.Error("anyOf — OR: оба условия ложны, remove не должен срабатывать")
	}
}

// TestCompileFileRulesCompositeRemovalUsesWhenWithAnd is the correct way to
// express composite removal (“neither kafka nor rabbitmq”) in the current
// mini-language: conjunction through && in one when, not anyOf.
func TestCompileFileRulesCompositeRemovalUsesWhenWithAnd(t *testing.T) {
	rules := []manifest.FileRule{
		{When: "brokers!=kafka && brokers!=rabbitmq", Remove: []string{"internal/integrations/**"}},
	}

	gs, err := compileFileRules(rules, settings.Values{"brokers": []string{}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if !gs.matchAny("internal/integrations/events/consumer.go") {
		t.Error("ни kafka, ни rabbitmq не выбраны — remove должен сработать")
	}

	gs, err = compileFileRules(rules, settings.Values{"brokers": []string{"kafka"}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if gs.matchAny("internal/integrations/events/consumer.go") {
		t.Error("kafka выбрана — remove не должен сработать")
	}
}

func TestCompileFileRulesUnknownGroupErrors(t *testing.T) {
	rules := []manifest.FileRule{
		{When: "nope=x", Paths: []string{"a/**"}},
	}
	if _, err := compileFileRules(rules, settings.Values{}); err == nil {
		t.Error("expected error for unknown group in when")
	}
}

func TestCompileFileRulesNoConditionIsNoop(t *testing.T) {
	rules := []manifest.FileRule{{Paths: []string{"a/**"}}}
	gs, err := compileFileRules(rules, settings.Values{})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if !gs.matchAny("a/b.txt") {
		t.Error("rule without when/anyOf evaluates to false, so paths are excluded")
	}
}
