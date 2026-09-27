package settings

import (
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// loadFixture loads and validates a package manifest fixture.
func loadFixture(t *testing.T, name string) *manifest.Template {
	t.Helper()
	tpl, err := manifest.LoadTemplate(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", name, err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatalf("фикстура %s невалидна: %v", name, err)
	}
	return tpl
}

// loadRepoFixture loads a fixture from the shared repository testdata.
func loadRepoFixture(t *testing.T, name string) *manifest.Template {
	t.Helper()
	tpl, err := manifest.LoadTemplate(filepath.Join("..", "..", "testdata", "manifest", name))
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", name, err)
	}
	return tpl
}
