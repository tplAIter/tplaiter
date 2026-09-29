package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/exports"
)

func TestReadBoundedRejectsNonRegularAndOversized(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.json")
	if err := os.WriteFile(small, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(small); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(dir); err == nil {
		t.Fatal("directory accepted")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", (1<<20)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(big); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestStrictInputRejectsDuplicateUnknownAndTrailing(t *testing.T) {
	var r struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Kind     string `json:"kind"`
		Evidence string `json:"evidence"`
		Declared bool   `json:"declared"`
		Detected bool   `json:"detected"`
	}
	for _, raw := range []string{`{"from":"a","from":"b","to":"b","kind":"x","evidence":"e","declared":true}`, `{"from":"a","to":"b","kind":"x","evidence":"e","declared":true,"extra":1}`, `{"from":"a","to":"b","kind":"x","evidence":"e","declared":true} {}`} {
		if err := canonicaljson.DecodeStrict([]byte(raw), &r); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestExportTopologyAndCompactPackBoundary(t *testing.T) {
	g := exports.ExportGraph{Selected: []exports.SelectedExport{{ID: "a", Name: "a"}, {ID: "a", Name: "b"}}}
	if validateExportGraph(g) == nil {
		t.Fatal("duplicate selected accepted")
	}
	g = exports.ExportGraph{Selected: []exports.SelectedExport{{ID: "a", Name: "a"}}, Edges: []exports.ExportEdge{{Dependency: "a", Consumer: "missing"}}}
	if validateExportGraph(g) == nil {
		t.Fatal("unknown endpoint accepted")
	}
	for _, n := range []int{1, contextpack.HardLimit - 1, contextpack.HardLimit, contextpack.HardLimit + 1} {
		p := contextpack.Pack{APIVersion: "v", GraphDigest: "g", Diagnostics: []string{strings.Repeat("é", n)}}
		var raw []byte
		for i := 0; i < 8; i++ {
			raw, _ = json.Marshal(p)
			if p.Bytes == len(raw) {
				break
			}
			p.Bytes = len(raw)
		}
		raw, _ = json.Marshal(p)
		if len(raw) != p.Bytes {
			t.Fatalf("accounting changed for %d: %d/%d", n, p.Bytes, len(raw))
		}
	}
}
