package settings

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSet_Types(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	tests := []struct {
		expr      string
		wantGroup string
		wantVal   any
	}{
		{"database=postgres", "database", "postgres"},
		{"brokers=kafka,rabbitmq", "brokers", []string{"kafka", "rabbitmq"}},
		{"brokers=kafka", "brokers", []string{"kafka"}},
		{"idempotency=true", "idempotency", true},
		{"idempotency=no", "idempotency", false},
		{"pg_shards=8", "pg_shards", 8},
	}
	for _, tc := range tests {
		g, v, err := ParseSet(tpl, tc.expr)
		if err != nil {
			t.Errorf("ParseSet(%q): %v", tc.expr, err)
			continue
		}
		if g != tc.wantGroup {
			t.Errorf("ParseSet(%q) group = %q, ожидалось %q", tc.expr, g, tc.wantGroup)
		}
		if !reflect.DeepEqual(v, tc.wantVal) {
			t.Errorf("ParseSet(%q) value = %#v, ожидалось %#v", tc.expr, v, tc.wantVal)
		}
	}
}

func TestParseSet_Errors(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	tests := []struct {
		expr string
		want string
	}{
		{"database", "формате group=value"},
		{"nosuch=x", "неизвестная группа"},
		{"database=oracle", "допустимо: none, postgres, mysql"},
		{"idempotency=maybe", "не булево"},
		{"pg_shards=many", "не является целым"},
		{"brokers=kafka,nats", "допустимо: kafka, rabbitmq"},
	}
	for _, tc := range tests {
		_, _, err := ParseSet(tpl, tc.expr)
		if err == nil {
			t.Errorf("ParseSet(%q): ожидалась ошибка", tc.expr)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSet(%q) ошибка %q не содержит %q", tc.expr, err.Error(), tc.want)
		}
	}
}

func TestParseSet_PlannedOptionRejected(t *testing.T) {
	tpl := loadRepoFixture(t, "full.yaml") // mysql помечена planned
	_, _, err := ParseSet(tpl, "database=mysql")
	if err == nil || !strings.Contains(err.Error(), "planned") {
		t.Fatalf("planned-опция должна отклоняться, получено: %v", err)
	}
}

func TestTypeAnswers_Native(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	raw := map[string]any{
		"database":    "postgres",
		"brokers":     []any{"kafka"},
		"idempotency": true,
		"pg_shards":   16,
	}
	got, err := typeAnswers(tpl, raw)
	if err != nil {
		t.Fatalf("typeAnswers: %v", err)
	}
	want := Values{
		"database":    "postgres",
		"brokers":     []string{"kafka"},
		"idempotency": true,
		"pg_shards":   16,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("typeAnswers = %#v, ожидалось %#v", got, want)
	}
}

func TestTypeAnswers_UnknownGroups(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	_, err := typeAnswers(tpl, map[string]any{"bogus": 1, "database": "none"})
	if err == nil || !strings.Contains(err.Error(), "неизвестные группы") {
		t.Fatalf("ожидалась ошибка про неизвестные группы, получено: %v", err)
	}
}
