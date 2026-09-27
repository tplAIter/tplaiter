package manifest

import (
	"encoding/json"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

const schemaPath = "../../schema/template.manifest.schema.json"

// TestSchema_ValidJSON: схема — синтаксически валидный JSON с ожидаемым каркасом.
//
// Решение по валидации: НЕ тянем внешний валидатор JSON Schema
// (santhosh-tekuri/jsonschema) ради одного теста — это добавило бы транзитивные
// зависимости в go.mod. Вместо этого проверяем схему как валидный JSON плюс
// smoke-покрытие: каждое поле верхнего уровня из полного примера (full.yaml)
// присутствует в properties схемы. Полноценную JSON Schema-валидацию против
// IDE делегируем редактору по $schema/$id.
func TestSchema_ValidJSON(t *testing.T) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("чтение схемы: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("схема не является валидным JSON: %v", err)
	}
	for _, key := range []string{"$schema", "$id", "type", "properties", "required", "$defs"} {
		if _, ok := schema[key]; !ok {
			t.Errorf("в схеме отсутствует ключ %q", key)
		}
	}
}

func TestSchema_CoversFullExample(t *testing.T) {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("чтение схемы: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatalf("разбор схемы: %v", err)
	}

	fullData, err := os.ReadFile(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("чтение full.yaml: %v", err)
	}
	var full map[string]any
	if err := yaml.Unmarshal(fullData, &full); err != nil {
		t.Fatalf("разбор full.yaml: %v", err)
	}

	for key := range full {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("поле верхнего уровня %q из full.yaml не покрыто схемой", key)
		}
	}
}
