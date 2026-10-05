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
			t.Errorf("ParseSet(%q) group = %q, expected %q", tc.expr, g, tc.wantGroup)
		}
		if !reflect.DeepEqual(v, tc.wantVal) {
			t.Errorf("ParseSet(%q) value = %#v, expected %#v", tc.expr, v, tc.wantVal)
		}
	}
}

func TestParseSet_Errors(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	tests := []struct {
		expr string
		want string
	}{
		{"database", "group=value format"},
		{"nosuch=x", "unknown group"},
		{"database=oracle", "allowed: none, postgres, mysql"},
		{"idempotency=maybe", "not boolean"},
		{"pg_shards=many", "not an integer"},
		{"brokers=kafka,nats", "allowed: kafka, rabbitmq"},
	}
	for _, tc := range tests {
		_, _, err := ParseSet(tpl, tc.expr)
		if err == nil {
			t.Errorf("ParseSet(%q): expected error", tc.expr)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSet(%q) error %q does not contain %q", tc.expr, err.Error(), tc.want)
		}
	}
}

func TestParseSet_PlannedOptionRejected(t *testing.T) {
	tpl := loadRepoFixture(t, "full.yaml") // mysql is marked planned
	_, _, err := ParseSet(tpl, "database=mysql")
	if err == nil || !strings.Contains(err.Error(), "planned") {
		t.Fatalf("a planned option must be rejected, got: %v", err)
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
		t.Errorf("typeAnswers = %#v, expected %#v", got, want)
	}
}

func TestTypeAnswers_UnknownGroups(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	_, err := typeAnswers(tpl, map[string]any{"bogus": 1, "database": "none"})
	if err == nil || !strings.Contains(err.Error(), "unknown groups") {
		t.Fatalf("expected error about unknown groups, got: %v", err)
	}
}

func TestDeprecatedCodecsUseCurrentRecordsOnly(t *testing.T) {
	tpl := deprecatedResolverTemplate()
	for _, expr := range []string{"choice=old", "multi=old,new", "retired=false"} {
		if _, _, err := ParseSet(tpl, expr); err == nil {
			t.Fatal("fresh codec admitted", expr)
		}
		if _, _, err := ParseRecordedSet(tpl, expr, Values{"choice": "old", "multi": []string{"old"}, "retired": false}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := typeAnswers(tpl, map[string]any{"choice": "old"}); err == nil {
		t.Fatal("answers file became prior authority")
	}
	if _, _, err := ParseRecordedSet(tpl, "choice=old", Values{"choice": "new"}); err == nil {
		t.Fatal("old history became retention authority")
	}
}

func TestDeprecatedFreshSupportedCodecsRemainAvailable(t *testing.T) {
	tpl := deprecatedResolverTemplate()
	for _, expr := range []string{"choice=new", "multi=new"} {
		if _, _, err := ParseSet(tpl, expr); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := typeAnswers(tpl, map[string]any{"choice": "new", "multi": []any{"new"}}); err != nil {
		t.Fatal(err)
	}
}
