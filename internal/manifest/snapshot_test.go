package manifest

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"
)

// TestSnapshot_Roundtrip проверяет стабильность сериализации: снимок,
// перечитанный и сериализованный заново, байт-в-байт совпадает с исходным.
// Сравниваем именно сериализованный вид (а не DeepEqual структур), т.к. теги
// yaml намеренно без omitempty — иначе `default: false` терялся бы, — поэтому
// пустой и nil-слайс на входе неразличимы после нормализации маршалером.
func TestSnapshot_Roundtrip(t *testing.T) {
	orig, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}

	path := filepath.Join(t.TempDir(), SnapshotRelPath)
	if err := SaveSnapshot(path, orig); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
	first, err := MarshalTemplate(orig)
	if err != nil {
		t.Fatalf("MarshalTemplate: %v", err)
	}

	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	second, err := MarshalTemplate(got)
	if err != nil {
		t.Fatalf("MarshalTemplate: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("сериализация не стабильна после roundtrip\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	// Значимые нормализованные структуры совпадают (второй прогон load).
	got2, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, got2) {
		t.Error("повторная загрузка снимка дала иную структуру")
	}
}

func TestSnapshot_LoadValidates(t *testing.T) {
	// Снимок проходит те же гейты apiVersion/kind, что и обычный манифест.
	orig, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), SnapshotRelPath)
	if err := SaveSnapshot(path, orig); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("восстановленный из снимка манифест не валиден: %v", err)
	}
}
