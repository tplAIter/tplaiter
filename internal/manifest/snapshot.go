package manifest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SnapshotRelPath is the manifest snapshot path relative to the project root.
// The snapshot enables offline `tplater run`/`gen` without access to the
// template repository.
const SnapshotRelPath = ".tplaiter/manifest.snapshot.yaml"

// SaveSnapshot serializes the template manifest as-is to path, creating parent
// directories. File mode is 0644 and directory mode is 0755.
func SaveSnapshot(path string, t *Template) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating snapshot directory: %w", err)
	}
	data, err := MarshalTemplate(t)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: the manifest is not secret; 0644 is intentional.
		return fmt.Errorf("writing snapshot %s: %w", path, err)
	}
	return nil
}

// LoadSnapshot reads and parses a manifest snapshot (strict decoding and gates,
// as in [LoadTemplate]).
func LoadSnapshot(path string) (*Template, error) {
	return LoadTemplate(path)
}

// MarshalTemplate serializes the manifest to YAML with two-space indentation.
func MarshalTemplate(t *Template) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(t); err != nil {
		return nil, fmt.Errorf("serializing manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("closing manifest encoder: %w", err)
	}
	return buf.Bytes(), nil
}
