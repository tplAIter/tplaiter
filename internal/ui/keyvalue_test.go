package ui

import (
	"strings"
	"testing"
)

func TestKeyValue_AlignsToLongestKey(t *testing.T) {
	kv := NewKeyValue().
		Add("репозиторий", "a").
		Add("версия", "v1.0.0").
		Add("описание", "Demo alpha template").
		Add("maintainers", "Alice <alice@example.com>").
		Add("labels", "infra=kafka; lang=go")

	got := kv.String()
	for _, want := range []string{
		"репозиторий: a",
		"версия:      v1.0.0",
		"описание:    Demo alpha template",
		"maintainers: Alice <alice@example.com>",
		"labels:      infra=kafka; lang=go",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("KeyValue.String() does not contain %q:\n%s", want, got)
		}
	}
}

func TestKeyValue_Indent(t *testing.T) {
	kv := NewKeyValue().Add("k", "v")
	got := kv.String()
	if !strings.HasPrefix(got, "  k:") {
		t.Errorf("KeyValue.String() = %q, want 2-space indent prefix", got)
	}
}

func TestKeyValue_Empty(t *testing.T) {
	kv := NewKeyValue()
	if got := kv.String(); got != "" {
		t.Errorf("empty KeyValue.String() = %q, want empty", got)
	}
}
