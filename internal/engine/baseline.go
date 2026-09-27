package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BaselineSchema — версия схемы Baseline.
const BaselineSchema = 1

// BaselineRelPath — путь baseline-файла относительно корня проекта (
// §8: `baseline: .tplaiter/baseline.json` в проектном маркере).
const BaselineRelPath = ".tplaiter/baseline.json"

// Baseline — снимок сгенерированного дерева для update-механики: sha256
// каждого файла + версия шаблона + хэш контекста рендера. Состав идентичен
// go-template'овскому — реализация  (update/diff) переносится на нём без
// изменений. Карта Files сериализуется детерминированно (encoding/json
// сортирует строковые ключи), поэтому два рендера с одинаковым входом дают
// побайтово идентичный baseline.
type Baseline struct {
	Schema          int               `json:"schema"`
	TemplateVersion string            `json:"templateVersion"`
	ContextHash     string            `json:"contextHash"`
	Files           map[string]string `json:"files"`
}

// ComputeBaseline вычисляет sha256-хэши перечисленных файлов (относительные
// пути) внутри dir. Возвращает карту relpath→hex(sha256).
func ComputeBaseline(dir string, files []string) (map[string]string, error) {
	out := make(map[string]string, len(files))
	for _, rel := range files {
		h, err := hashFile(filepath.Join(dir, rel))
		if err != nil {
			return nil, fmt.Errorf("engine: hash %s: %w", rel, err)
		}
		out[rel] = h
	}
	return out, nil
}

// hashFile возвращает hex-представление sha256 содержимого файла.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashContext возвращает sha256 канонического JSON-представления контекста
// рендера.
func hashContext(c *Context) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("engine: marshal context: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Save сериализует baseline в dir/.tplaiter/baseline.json (отступ 2 пробела,
// финальный \n).
func (b *Baseline) Save(dir string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: marshal baseline: %w", err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, filepath.FromSlash(BaselineRelPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("engine: mkdir baseline dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("engine: write baseline: %w", err)
	}
	return nil
}
