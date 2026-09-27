package settings

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestReport_GoldenSerialization фиксирует стабильную YAML-сериализацию доклада
// резолвера. Порядок Implied и Warnings детерминирован (сортировка в Resolve),
// поэтому golden-файл воспроизводим. Обновление: TPLAITER_UPDATE_GOLDEN=1.
func TestReport_GoldenSerialization(t *testing.T) {
	tpl := loadFixture(t, "nested3.yaml")
	res, err := Resolve(tpl, Values{
		"auth":      []string{"sso_provider"},
		"kafka_ssl": true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got, err := yaml.Marshal(res.Report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	golden := filepath.Join("testdata", "golden", "report.yaml")
	if os.Getenv("TPLAITER_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("чтение golden (запусти с TPLAITER_UPDATE_GOLDEN=1 для генерации): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("сериализация Report не совпала с golden:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
