package state

import (
	"os"
	"path/filepath"
	"testing"
)

// readDirNames возвращает имена файлов/каталогов непосредственно внутри dir
// (без рекурсии) — используется, чтобы убедиться, что временные файлы
// writeFileAtomic не остаются после успешной записи.
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// writeRaw записывает содержимое content в файл name внутри home напрямую
// (в обход Save*), чтобы тесты могли подсунуть повреждённый/будущий/старый
// YAML и проверить поведение Load*.
func writeRaw(t *testing.T, home, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writeRaw(%q): %v", name, err)
	}
}
