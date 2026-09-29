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
		t.Fatalf("groups in defaults = %d, expected %d: %#v", len(got), len(want), got)
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("group %q missing from defaults", k)
			continue
		}
		if !reflect.DeepEqual(gv, wv) {
			t.Errorf("group %q = %#v (%T), expected %#v (%T)", k, gv, gv, wv, wv)
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
			t.Errorf("group %q = %#v, expected %#v", k, got[k], wv)
		}
	}
}

func TestValues_Clone_IsolatesSlices(t *testing.T) {
	v := Values{"brokers": []string{"kafka"}}
	c := v.Clone()
	c["brokers"].([]string)[0] = "rabbitmq"
	if v["brokers"].([]string)[0] != "kafka" {
		t.Errorf("Clone did not isolate the slice: %v", v["brokers"])
	}
}
