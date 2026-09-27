package manifest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SnapshotRelPath — путь снимка манифеста относительно корня проекта. Снимок
// нужен для офлайн-исполнения `tplater run`/`gen` без доступа к репозиторию
// шаблона.
const SnapshotRelPath = ".tplaiter/manifest.snapshot.yaml"

// SaveSnapshot сериализует манифест шаблона как есть в path (создавая
// родительские каталоги). Права файла 0644, каталогов — 0755.
func SaveSnapshot(path string, t *Template) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("создание каталога снимка: %w", err)
	}
	data, err := MarshalTemplate(t)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: манифест не секрет, 0644 намеренно.
		return fmt.Errorf("запись снимка %s: %w", path, err)
	}
	return nil
}

// LoadSnapshot читает и разбирает снимок манифеста (строгий разбор + гейты, как
// у [LoadTemplate]).
func LoadSnapshot(path string) (*Template, error) {
	return LoadTemplate(path)
}

// MarshalTemplate сериализует манифест в YAML с отступом в 2 пробела.
func MarshalTemplate(t *Template) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(t); err != nil {
		return nil, fmt.Errorf("сериализация манифеста: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("закрытие энкодера манифеста: %w", err)
	}
	return buf.Bytes(), nil
}
