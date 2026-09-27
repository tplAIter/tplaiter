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

// TestCompileFileRulesAnyOfIsOr фиксирует семантику anyOf: список условий
// объединяется через settings.EvalAny — OR, а НЕ AND (несмотря на то, что имя
// поля "anyOf" наводит на противоположную интуицию, а
// иллюстрирует anyOf примером композитного удаления, для которого нужен
// именно AND — см. описание поведения ). Композитное удаление («ни кафка, ни
// раббит») выражается ОДНИМ `when` с `&&` (settings.Eval), не через anyOf.
func TestCompileFileRulesAnyOfIsOr(t *testing.T) {
	rules := []manifest.FileRule{
		{AnyOf: []string{"database=postgres", "brokers=kafka"}, Remove: []string{"legacy/**"}},
	}

	// Истинен только первый атом (database=postgres) — OR всё равно true.
	gs, err := compileFileRules(rules, settings.Values{"database": "postgres", "brokers": []string{}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if !gs.matchAny("legacy/notice.txt") {
		t.Error("anyOf — OR: истинности одного условия достаточно, remove должен сработать")
	}

	// Оба атома ложны — OR ложен, remove не срабатывает.
	gs, err = compileFileRules(rules, settings.Values{"database": "none", "brokers": []string{}})
	if err != nil {
		t.Fatalf("compileFileRules: %v", err)
	}
	if gs.matchAny("legacy/notice.txt") {
		t.Error("anyOf — OR: оба условия ложны, remove не должен срабатывать")
	}
}

// TestCompileFileRulesCompositeRemovalUsesWhenWithAnd — правильный способ
// выразить композитное удаление («ни kafka, ни rabbitmq») в текущем
// мини-языке: конъюнкция через && внутри одного when, не anyOf.
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
