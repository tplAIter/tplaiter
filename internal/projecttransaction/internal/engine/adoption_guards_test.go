//go:build darwin || linux

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func TestAdoptionScopeCannotPromoteV1OrDetachedV2Intent(t *testing.T) {
	tx, _, _, _ := signedUpdateEngine(t)
	defer tx.Release()
	name := filepath.Join(tx.dir, "state.json")
	before, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	original := bytes.Clone(tx.plan.Material.Intent)
	if _, e = ScopeAdoption(context.Background(), tx); e == nil {
		t.Fatal("v1 acquired v2 authority")
	}
	var detached map[string]any
	if e = json.Unmarshal(original, &detached); e != nil {
		t.Fatal(e)
	}
	detached["version"] = 2
	detached["protection"] = map[string]any{"decisionSHA256": "sha256:caller"}
	tx.plan.Material.Intent, e = canonicaljson.Canonical(detached)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ScopeAdoption(context.Background(), tx); e == nil {
		t.Fatal("detached v2 claims acquired authority")
	}
	after, e := os.ReadFile(name)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal advanced receipt", e)
	}
	tx.plan.Material.Intent = original
	if e = tx.Commit(context.Background()); e != nil {
		t.Fatal("unchanged v1 engine failed", e)
	}
}
