package settings

import (
	"reflect"
	"testing"
)

func TestDefaultValues_Nested3(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	got := DefaultValues(tpl)

	want := Values{
		"database":    "none",
		"pg_pool":     "small",
		"pg_shards":   4,
		"idempotency": false,
		"brokers":     []string{},
		"kafka_ssl":   false,
		"auth":        []string{},
		"metrics":     false,
		"extras":      []string{},
	}
	if len(got) != len(want) {
		t.Fatalf("групп в дефолтах = %d, ожидалось %d: %#v", len(got), len(want), got)
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("нет группы %q в дефолтах", k)
			continue
		}
		if !reflect.DeepEqual(gv, wv) {
			t.Errorf("группа %q = %#v (%T), ожидалось %#v (%T)", k, gv, gv, wv, wv)
		}
	}
}

func TestDefaultValues_FullFixture(t *testing.T) {
	tpl := loadRepoFixture(t, "full.yaml")
	got := DefaultValues(tpl)

	// Nested groups always receive defaults, regardless of the parent's choice.
	checks := map[string]any{
		"database":     "none",
		"idempotency":  false,
		"brokers":      []string{},
		"kafka_ssl":    false,
		"kafka_cdc":    false,
		"kafka_topics": "",
		"auth":         []string{},
	}
	for k, wv := range checks {
		if !reflect.DeepEqual(got[k], wv) {
			t.Errorf("группа %q = %#v, ожидалось %#v", k, got[k], wv)
		}
	}
}

func TestValues_Clone_IsolatesSlices(t *testing.T) {
	v := Values{"brokers": []string{"kafka"}}
	c := v.Clone()
	c["brokers"].([]string)[0] = "rabbitmq"
	if v["brokers"].([]string)[0] != "kafka" {
		t.Errorf("Clone не изолировал срез: %v", v["brokers"])
	}
}
