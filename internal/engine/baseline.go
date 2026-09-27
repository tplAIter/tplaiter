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

// BaselineSchema is the Baseline schema version.
const BaselineSchema = 1

// BaselineRelPath is the baseline file path relative to the project root
// (§8: `baseline: .tplaiter/baseline.json` in the project marker).
const BaselineRelPath = ".tplaiter/baseline.json"

// Baseline is a snapshot of the generated tree for the update mechanism: the
// sha256 hash of each file, the template version, and the render-context hash.
// Its structure matches go-template's; the  (update/diff) implementation is
// carried over unchanged. Files is serialized deterministically (encoding/json
// sorts string keys), so renders with identical input produce byte-identical
// baselines.
type Baseline struct {
	Schema          int               `json:"schema"`
	TemplateVersion string            `json:"templateVersion"`
	ContextHash     string            `json:"contextHash"`
	Files           map[string]string `json:"files"`
}

// ComputeBaseline computes sha256 hashes for the listed files (relative paths)
// inside dir. It returns a relpath→hex(sha256) map.
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

// hashFile returns the hexadecimal sha256 representation of the file contents.
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

// hashContext returns the sha256 hash of the canonical JSON representation of
// the render context.
func hashContext(c *Context) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("engine: marshal context: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Save serializes the baseline to dir/.tplaiter/baseline.json (two-space
// indentation and a final \n).
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
